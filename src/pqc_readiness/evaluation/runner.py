"""Evaluation runner over the public corpus."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from pqc_readiness.evaluation.eligibility import eligible_project_files
from pqc_readiness.evaluation.ground_truth import load_ground_truth
from pqc_readiness.evaluation.keys import evaluation_key
from pqc_readiness.evaluation.metrics import (
    EvaluationResult,
    aggregate_project_metrics,
    verify_scorer_sanity,
)
from pqc_readiness.findings import dedupe_findings
from pqc_readiness.models import CryptoFinding, EvidenceSource
from pqc_readiness.scanners.codebase import scan_source_file
from pqc_readiness.scanners.config import scan_config_file
from pqc_readiness.scanners.ssh import scan_ssh_known_hosts
from pqc_readiness.scanners.x509 import scan_x509_file


@dataclass
class ProjectScanOutput:
    """Scan output keyed for evaluation."""

    project_id: str
    predicted_keys: set[str]
    findings: list[CryptoFinding]


def scan_evaluation_project(corpus_dir: Path, project_id: str) -> ProjectScanOutput:
    """Run all applicable scanners on one evaluation project directory."""
    project_path = corpus_dir / project_id
    findings: list[CryptoFinding] = []
    for path, source in eligible_project_files(project_path):
        if source == EvidenceSource.CODE:
            findings.extend(scan_source_file(path))
        elif source == EvidenceSource.CONFIG:
            findings.extend(scan_config_file(path))
        elif source == EvidenceSource.SSH:
            findings.extend(scan_ssh_known_hosts(path))
        else:
            findings.extend(scan_x509_file(str(path)))

    findings = dedupe_findings(findings)
    predicted: set[str] = set()
    for finding in findings:
        key = evaluation_key(project_id, finding)
        predicted.add(key)
        finding.metadata["eval_key"] = key

    return ProjectScanOutput(project_id=project_id, predicted_keys=predicted, findings=findings)


def predicted_keys_by_project(scan_outputs: list[ProjectScanOutput]) -> dict[str, set[str]]:
    """Collect location-aware predicted keys per project."""
    return {output.project_id: set(output.predicted_keys) for output in scan_outputs}


def run_evaluation(
    corpus_dir: Path,
    ground_truth_path: Path,
    *,
    seed: int = 42,
    n_bootstrap: int = 1000,
) -> tuple[EvaluationResult, dict[str, Any]]:
    """Run full evaluation pipeline."""
    verify_scorer_sanity()
    corpus = load_ground_truth(ground_truth_path)
    project_ids = sorted({item.project_id for item in corpus.items})
    scans = [scan_evaluation_project(corpus_dir, pid) for pid in project_ids]
    predicted = predicted_keys_by_project(scans)
    expected = corpus.expected_keys_by_project()
    result = aggregate_project_metrics(predicted, expected, seed=seed, n_bootstrap=n_bootstrap)
    payload: dict[str, Any] = {
        "seed": seed,
        "n_bootstrap": n_bootstrap,
        "licence": corpus.licence,
        "provenance": corpus.provenance,
        "metric_scope": "algorithm_presence_by_location",
        "precision": asdict(result.precision),
        "recall": asdict(result.recall),
        "f1": asdict(result.f1),
        "per_project": {
            pid: {
                "precision": m.precision,
                "recall": m.recall,
                "f1": m.f1,
                "tp": m.true_positives,
                "fp": m.false_positives,
                "fn": m.false_negatives,
                "support": m.support,
            }
            for pid, m in result.per_project.items()
        },
    }
    return result, payload


def write_evaluation_results(payload: dict[str, Any], output_path: Path) -> None:
    """Write JSON results."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
