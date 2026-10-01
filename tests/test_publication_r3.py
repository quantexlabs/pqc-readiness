"""Behavioral and release-contract regressions for round 3."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from pqc_readiness.cbom.builder import finding_to_component
from pqc_readiness.classification.priority import build_migration_plan, score_migration_priority
from pqc_readiness.evaluation.baseline import baseline_scan_project
from pqc_readiness.models import (
    CryptoFinding,
    EvidenceSource,
    MigrationPriority,
    QuantumRisk,
    ScanResult,
    SensitivityClass,
)
from pqc_readiness.pipeline import PipelineConfig, run_pipeline, write_pipeline_outputs
from pqc_readiness.report.html import render_report
from pqc_readiness.scanners.codebase import scan_source_file

ROOT = Path(__file__).resolve().parents[1]


def observation(algo: str = "ML-KEM", size: int | None = None) -> CryptoFinding:
    return CryptoFinding(
        "one",
        EvidenceSource.CODE,
        algo,
        size,
        "app.py:1",
        "marker",
        QuantumRisk.UNKNOWN,
        MigrationPriority.MEDIUM,
    )


def test_r2_external_identity_and_relocation(tmp_path: Path) -> None:
    snapshots: list[list[tuple[str, str]]] = []
    for name in ("first", "relocated"):
        root = tmp_path / name
        for relative in ("a/main.py", "b/main.py"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("rsa.generate_private_key(key_size=2048)\n")
        scan = run_pipeline(PipelineConfig(code_dir=root, skip_tls=True))
        assert len(scan.findings) == 2
        assert len({f.finding_id for f in scan.findings}) == 2
        snapshots.append([(f.location, f.finding_id) for f in scan.findings])
    assert snapshots[0] == snapshots[1]


def test_r3_unparsed_sizes_and_md5(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("key = b'0123456789abcdef'\nAES.new(key, AES.MODE_GCM)\nhashlib.md5(b'x')\n")
    findings = scan_source_file(path)
    aes = next(f for f in findings if f.algorithm == "AES")
    assert aes.key_size is None
    assert aes.quantum_risk == QuantumRisk.UNKNOWN
    assert {f.algorithm for f in findings} == {"AES", "MD5"}


def test_r3_marker_outputs(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("# disabled ML-KEM-768\n")
    cfg = PipelineConfig(code_dir=tmp_path, skip_tls=True, output_dir=tmp_path / "out")
    scan = run_pipeline(cfg)
    assert scan.findings[0].quantum_risk == QuantumRisk.UNKNOWN
    paths = write_pipeline_outputs(scan, cfg)
    row = json.loads(paths["findings"].read_text())["findings"][0]
    assert row["metadata"]["observation"] == "lexical_marker"
    assert "lexical_marker" in paths["report"].read_text()
    assert "lexical_marker" in paths["cbom"].read_text()
    assert "Verify" in paths["plan"].read_text()


def test_r4_harvest_confidentiality_over_signature() -> None:
    common = (QuantumRisk.VULNERABLE, SensitivityClass.PUBLIC, 5, True)
    signature = score_migration_priority(*common, is_signature_use=True)
    confidentiality = score_migration_priority(*common, is_signature_use=False)
    assert signature == MigrationPriority.MEDIUM
    assert confidentiality == MigrationPriority.CRITICAL


def test_r5_no_unsupported_security_levels() -> None:
    for algo, size in (("ML-KEM", None), ("ECDSA", 256), ("Ed25519", 256), ("AES", None)):
        component = finding_to_component(observation(algo, size))
        props = component["cryptoProperties"]["algorithmProperties"]
        assert "classicalSecurityLevel" not in props
        assert "nistQuantumSecurityLevel" not in props
        if algo == "ML-KEM":
            assert props["primitive"] == "kem"


def test_r6_baseline_same_eligibility(tmp_path: Path) -> None:
    root = tmp_path / "project" / "certs"
    root.mkdir(parents=True)
    (root / "_gen_cert.py").write_text("RSA.generate(2048)\n")
    assert not baseline_scan_project(tmp_path, "project").findings


def test_r9_missing_paths_private(tmp_path: Path) -> None:
    cfg = PipelineConfig(
        code_dir=tmp_path / "missing",
        skip_tls=True,
        require_inputs=True,
        output_dir=tmp_path,
    )
    paths = write_pipeline_outputs(run_pipeline(cfg), cfg)
    for path in paths.values():
        assert ("/" + "Users" + "/") not in path.read_text()


def test_r10_malformed_and_tls_failure(tmp_path: Path) -> None:
    cert = tmp_path / "invalid.pem"
    cert.write_text("invalid certificate")
    with patch("pqc_readiness.pipeline.scan_tls_host", return_value=ScanResult(errors=["timeout"])):
        cfg = PipelineConfig(cert_paths=(cert,), tls_hosts=("badssl.com",))
        result = run_pipeline(cfg)
    assert len(result.coverage.failed_paths) == 2
    assert result.errors


def test_r10_display_limits() -> None:
    scan = ScanResult(findings=[replace(observation("RSA"), finding_id=str(i)) for i in range(501)])
    html = render_report(scan, build_migration_plan(scan.findings), {})
    assert "Showing 500 of 501 findings" in html
    assert "Showing 200 of 501 actions" in html
    assert scan.coverage.findings_truncated


@pytest.mark.parametrize(
    ("finding", "path", "required"),
    [
        (6, "docs/PREREGISTRATION.md", "Retrospective"),
        (7, "data/schemas/PROVENANCE.md", "Local modification"),
        (8, "REPORT.md", "PUBLICATION_FIX_REPORT_R4_2026-10-01.md"),
        (11, "scripts/regenerate_results.py", "--check"),
        (12, "README.md", "four local artifact classes"),
        (13, "data/DATA_MANIFEST.md", "results/latest"),
        (15, "README.md", "Independent validation remains blocked"),
    ],
)
def test_release_claim_contract(finding: int, path: str, required: str) -> None:
    target = ROOT / path
    assert target.exists(), f"finding {finding}: missing {path}"
    assert required in target.read_text(), f"finding {finding}: missing {required}"


@pytest.mark.parametrize(
    "case", json.loads((ROOT / "data/evaluation/regression_cases.json").read_text())
)
def test_attribute_and_negative_cases(tmp_path: Path, case: dict[str, object]) -> None:
    path = tmp_path / "case.py"
    path.write_text(str(case["source"]))
    findings = scan_source_file(path)
    assert sorted({f.algorithm for f in findings}) == case["algorithms"]
    assert all(f.key_size == case["size"] for f in findings)


def test_external_cert_ssh_roots_and_relocation(tmp_path: Path) -> None:
    snapshots: list[list[tuple[str, str]]] = []
    fixture = ROOT / "data/evaluation/corpus/proj_rsa_app/certs/rsa2048.pem"
    for name in ("original", "relocated"):
        root = tmp_path / name
        roots = [root / "a", root / "b"]
        for directory in roots:
            directory.mkdir(parents=True)
            (directory / "same.pem").write_bytes(fixture.read_bytes())
        hosts = root / "known_hosts"
        hosts.write_text("demo.test ssh-ed25519 ZmFrZQ==\n")
        scan = run_pipeline(
            PipelineConfig(
                cert_paths=tuple(directory / "same.pem" for directory in roots),
                known_hosts=hosts,
                skip_tls=True,
            )
        )
        assert len(scan.findings) == 5
        assert len({f.finding_id for f in scan.findings}) == 5
        assert scan.coverage.files_scanned == 3
        snapshots.append([(f.location, f.finding_id) for f in scan.findings])
    assert snapshots[0] == snapshots[1]


def test_fixture_coverage_units() -> None:
    scan = run_pipeline(PipelineConfig(corpus_dir=ROOT / "data/evaluation/corpus", skip_tls=True))
    coverage = scan.coverage.to_dict()
    assert coverage["requested_targets"] == 1
    assert coverage["scanned_count"] == 1
    assert coverage["projects_scanned"] == 4
    assert coverage["files_scanned"] == 7


def test_tls_host_cap_and_partial_exit(tmp_path: Path) -> None:
    from pqc_readiness.cli import main
    from pqc_readiness.constants import MAX_TLS_HOSTS

    with patch("pqc_readiness.pipeline.scan_tls_host", return_value=ScanResult()):
        scan = run_pipeline(PipelineConfig(tls_hosts=("demo.test",) * (MAX_TLS_HOSTS + 1)))
    assert scan.coverage.to_dict()["status"] == "partial"
    assert len(scan.coverage.skipped_paths) == 1
    assert (
        main(
            [
                "scan",
                "--skip-tls",
                "--code-dir",
                str(tmp_path / "missing"),
                "--output-dir",
                str(tmp_path / "out"),
            ]
        )
        == 2
    )


def test_unknown_use_and_harvest_scenarios() -> None:
    from pqc_readiness.classification.priority import finding_use

    finding = replace(observation("RSA"), quantum_risk=QuantumRisk.VULNERABLE)
    assert finding_use(finding) == "unknown"
    common = (QuantumRisk.VULNERABLE, SensitivityClass.PUBLIC, 5, True)
    assert score_migration_priority(*common, use="signature") == MigrationPriority.MEDIUM
    assert score_migration_priority(*common, use="unknown") == MigrationPriority.MEDIUM
    assert score_migration_priority(*common, use="key_establishment") == MigrationPriority.CRITICAL
    assert "use unknown" in build_migration_plan([finding]).actions[0].rationale


def test_security_fields_omitted_for_classified_algorithms() -> None:
    for algo, size, risk in (
        ("ECDSA", 256, QuantumRisk.VULNERABLE),
        ("Ed25519", 256, QuantumRisk.VULNERABLE),
        ("ML-KEM", None, QuantumRisk.SAFE),
        ("AES", 128, QuantumRisk.REDUCED),
    ):
        component = finding_to_component(replace(observation(algo, size), quantum_risk=risk))
        props = component["cryptoProperties"]["algorithmProperties"]
        assert "classicalSecurityLevel" not in props
        assert "nistQuantumSecurityLevel" not in props


def test_all_fixture_components_schema_valid() -> None:
    import jsonschema

    from pqc_readiness.cbom.builder import build_cbom

    scan = run_pipeline(PipelineConfig(corpus_dir=ROOT / "data/evaluation/corpus", skip_tls=True))
    schema = json.loads((ROOT / "data/schemas/bom-1.6.schema.json").read_text())
    jsonschema.validate(build_cbom(scan), schema)


def test_regeneration_rejects_stale_artifacts(tmp_path: Path) -> None:
    import shutil
    import subprocess
    import sys

    for name in ("src", "data", "scripts", "results"):
        shutil.copytree(ROOT / name, tmp_path / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    script = tmp_path / "scripts/regenerate_results.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--check"], cwd=tmp_path, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    target = tmp_path / "results/latest/findings.json"
    payload = json.loads(target.read_text())
    payload["findings"][0]["evidence"] = "deliberately stale evidence"
    target.write_text(json.dumps(payload))
    proc = subprocess.run(
        [sys.executable, str(script), "--check"], cwd=tmp_path, capture_output=True, text=True
    )
    assert proc.returncode == 1
    assert "results/latest/findings.json" in proc.stdout
