"""End-to-end inventory and reporting pipeline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pqc_readiness.cbom.builder import build_cbom
from pqc_readiness.classification.priority import build_migration_plan
from pqc_readiness.constants import DEFAULT_TLS_TEST_HOSTS, MAX_TLS_HOSTS
from pqc_readiness.coverage import ScanCoverage
from pqc_readiness.findings import apply_migration_priorities, dedupe_findings
from pqc_readiness.models import CryptoFinding, ScanResult, SensitivityClass
from pqc_readiness.report.html import render_report, write_report_html
from pqc_readiness.scanners.codebase import scan_code_directory
from pqc_readiness.scanners.config import scan_config_directory
from pqc_readiness.scanners.ssh import scan_ssh_known_hosts
from pqc_readiness.scanners.tls import scan_tls_host
from pqc_readiness.scanners.x509 import scan_x509_file


@dataclass
class PipelineConfig:
    """Configuration for a full scan pipeline."""

    tls_hosts: tuple[str, ...] = DEFAULT_TLS_TEST_HOSTS
    code_dir: Path | None = None
    config_dir: Path | None = None
    cert_paths: tuple[Path, ...] = ()
    known_hosts: Path | None = None
    corpus_dir: Path | None = None
    sensitivity: SensitivityClass = SensitivityClass.UNCLASSIFIED
    lifetime_years: int = 10
    harvest_exposure: bool = True
    output_dir: Path = Path("results/latest")
    project_name: str = "pqc-readiness-scan"
    skip_tls: bool = False
    require_inputs: bool = False


def _scan_scope(path: Path, label: str) -> tuple[Path, str]:
    """Use repository coordinates locally and opaque input slots externally."""
    from pqc_readiness.paths import find_repo_root

    repo = find_repo_root()
    if path.resolve().is_relative_to(repo):
        return repo, ""
    return (path if path.is_dir() else path.parent), label


def _local_scan(
    path: Path,
    label: str,
    kind: str,
    merged: ScanResult,
    *,
    required: bool = True,
    nested: bool = False,
) -> None:
    from pqc_readiness.constants import MAX_FILE_BYTES
    from pqc_readiness.paths import format_location

    root, namespace = _scan_scope(path, label)
    location = format_location(path, scan_root=root, namespace=namespace)
    coverage = merged.coverage
    if not path.exists() or (kind in {"code", "config", "corpus"} and not path.is_dir()):
        if required:
            merged.errors.append(f"Invalid or missing {label}: {location}")
            coverage.add_failed(location, "missing or wrong type")
        else:
            merged.warnings.append(f"Skipped missing {label}: {location}")
            coverage.add_skipped(location, "missing")
        return
    try:
        if kind == "corpus":
            merged.findings.extend(scan_fixture_corpus(path, coverage, merged))
        elif kind == "code":
            merged.findings.extend(
                scan_code_directory(
                    path,
                    coverage=coverage,
                    scan_root=root,
                    namespace=namespace,
                    errors=merged.errors,
                )
            )
        elif kind == "config":
            merged.findings.extend(
                scan_config_directory(
                    path,
                    coverage=coverage,
                    scan_root=root,
                    namespace=namespace,
                    errors=merged.errors,
                )
            )
        else:
            if path.stat().st_size > MAX_FILE_BYTES:
                coverage.files_skipped_size += 1
                coverage.add_skipped(location, "size limit")
                return
            if kind == "cert":
                observations = scan_x509_file(str(path), scan_root=root, namespace=namespace)
            else:
                observations = scan_ssh_known_hosts(path, scan_root=root, namespace=namespace)
            coverage.files_scanned += 1
            merged.findings.extend(observations)
        merged.scan_targets.append(location)
        coverage.local_targets_scanned += 1
        if not nested:
            coverage.add_scanned(location)
    except (OSError, ValueError) as exc:
        # Exception text can embed absolute local paths or input content.
        merged.errors.append(f"Failed {label}: {location} ({type(exc).__name__})")
        coverage.add_failed(location, type(exc).__name__)


def scan_fixture_corpus(
    corpus_dir: Path,
    coverage: ScanCoverage,
    merged: ScanResult | None = None,
) -> list[CryptoFinding]:
    """Scan local fixture artifacts, preserving failures per input."""
    result = merged if merged is not None else ScanResult(coverage=coverage)
    start = len(result.findings)
    if not corpus_dir.is_dir():
        return []
    for project_dir in sorted(p for p in corpus_dir.iterdir() if p.is_dir()):
        coverage.projects_scanned += 1
        for name, kind in (("src", "code"), ("config", "config"), ("ssh/known_hosts", "ssh")):
            path = project_dir / name
            if path.exists():
                _local_scan(path, project_dir.name + "/" + kind, kind, result, nested=True)
        for cert in sorted((project_dir / "certs").glob("*.pem")):
            if not cert.name.startswith("_"):
                _local_scan(
                    cert, project_dir.name + "/cert/" + cert.name, "cert", result, nested=True
                )
    # The caller extends its own findings only when using the standalone form.
    return result.findings[start:] if merged is None else []


def run_pipeline(config: PipelineConfig) -> ScanResult:
    """Run configured scanners, recording partial coverage explicitly."""
    merged = ScanResult()
    coverage = merged.coverage
    if not config.skip_tls:
        for index, host in enumerate(config.tls_hosts):
            label = f"tls-target-{index + 1}"
            coverage.add_requested(label)
            if index >= MAX_TLS_HOSTS:
                coverage.add_skipped(label, "host cap")
                continue
            tls_result = scan_tls_host(host)
            merged.findings.extend(tls_result.findings)
            # Host strings and mocked exception messages may contain local paths.
            if tls_result.errors:
                merged.errors.append(f"TLS scan failed: {label}")
                coverage.add_failed(label, "TLS error")
            else:
                coverage.add_scanned(label)
            merged.scan_targets.append(label)
    inputs: list[tuple[Path | None, str, str]] = [
        (config.corpus_dir, "corpus", "corpus"),
        (config.code_dir, "code", "code"),
        (config.config_dir, "config", "config"),
        (config.known_hosts, "ssh", "ssh"),
    ]
    inputs.extend((cert, f"cert-{i + 1}", "cert") for i, cert in enumerate(config.cert_paths))
    for path, label, kind in inputs:
        if path is not None:
            coverage.add_requested(label)
            _local_scan(
                path, label, kind, merged, required=config.require_inputs or kind == "corpus"
            )
    merged.findings = apply_migration_priorities(
        dedupe_findings(merged.findings),
        sensitivity=config.sensitivity,
        lifetime_years=config.lifetime_years,
        harvest_exposure=config.harvest_exposure,
    )
    coverage.findings_emitted = len(merged.findings)
    return merged


def write_pipeline_outputs(
    scan: ScanResult,
    config: PipelineConfig,
) -> dict[str, Path]:
    """Write CBOM, migration plan, and HTML report."""
    out = config.output_dir
    out.mkdir(parents=True, exist_ok=True)
    plan = build_migration_plan(
        scan.findings,
        sensitivity=config.sensitivity,
        default_lifetime_years=config.lifetime_years,
        harvest_exposure=config.harvest_exposure,
    )
    scan.coverage.findings_emitted = len(scan.findings)
    scan.coverage.findings_truncated = len(scan.findings) > 500
    scan.coverage.actions_emitted = len(plan.actions)
    cbom = build_cbom(scan, project_name=config.project_name)
    cbom_path = out / "inventory.cbom.json"
    cbom_path.write_text(json.dumps(cbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    plan_path = out / "migration_plan.json"
    plan_payload: dict[str, Any] = {
        "reference": plan.reference,
        "summary": plan.summary,
        "actions": [
            {
                "finding_id": a.finding_id,
                "priority": a.priority.value,
                "target_milestone": a.target_milestone.isoformat(),
                "action": a.action,
                "rationale": a.rationale,
            }
            for a in plan.actions
        ],
    }
    plan_path.write_text(
        json.dumps(plan_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    html_path = out / "report.html"
    write_report_html(html_path, render_report(scan, plan, cbom))

    scan_path = out / "findings.json"
    scan_path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "source": f.source.value,
                        "algorithm": f.algorithm,
                        "key_size": f.key_size,
                        "location": f.location,
                        "quantum_risk": f.quantum_risk.value,
                        "migration_priority": f.migration_priority.value,
                        "evidence": f.evidence,
                        "metadata": f.metadata,
                    }
                    for f in scan.findings
                ],
                "errors": scan.errors,
                "warnings": scan.warnings,
                "scan_targets": scan.scan_targets,
                "coverage": scan.coverage.to_dict(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "cbom": cbom_path,
        "plan": plan_path,
        "report": html_path,
        "findings": scan_path,
    }
