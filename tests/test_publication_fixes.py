"""Regression tests for publication review findings."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pqc_readiness.cbom.builder import build_cbom, finding_to_component
from pqc_readiness.classification.priority import classify_quantum_risk
from pqc_readiness.evaluation.keys import evaluation_key
from pqc_readiness.evaluation.metrics import compute_metrics
from pqc_readiness.evaluation.runner import scan_evaluation_project
from pqc_readiness.models import (
    CryptoFinding,
    EvidenceSource,
    MigrationPriority,
    QuantumRisk,
    ScanResult,
)
from pqc_readiness.pipeline import PipelineConfig, run_pipeline
from pqc_readiness.scanners.codebase import scan_source_file
from pqc_readiness.scanners.config import scan_config_file


def test_cbom_algorithm_properties_is_object() -> None:
    finding = CryptoFinding(
        finding_id="f1",
        source=EvidenceSource.CODE,
        algorithm="RSA",
        key_size=2048,
        location="data/app.py:1",
        evidence="rsa",
        quantum_risk=QuantumRisk.VULNERABLE,
        migration_priority=MigrationPriority.HIGH,
    )
    comp = finding_to_component(finding)
    algo = comp["cryptoProperties"]["algorithmProperties"]
    assert isinstance(algo, dict)
    assert "oid" not in comp["cryptoProperties"]
    ssh = finding_to_component(
        CryptoFinding(
            finding_id="f2",
            source=EvidenceSource.SSH,
            algorithm="Ed25519",
            key_size=256,
            location="data/known_hosts:1",
            evidence="ssh-ed25519",
            quantum_risk=QuantumRisk.VULNERABLE,
            migration_priority=MigrationPriority.HIGH,
        )
    )
    assert (
        ssh["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "public-key"
    )


def test_ed25519_classified_vulnerable() -> None:
    assert classify_quantum_risk("Ed25519", 256) == QuantumRisk.VULNERABLE
    assert classify_quantum_risk("SHA-256") == QuantumRisk.SAFE
    assert classify_quantum_risk("SHA256") == QuantumRisk.SAFE
    assert classify_quantum_risk("AES", 128) == QuantumRisk.REDUCED
    assert classify_quantum_risk("AES") == QuantumRisk.UNKNOWN


def test_rsa_key_size_parsed_from_generate_private_key(tmp_path: Path) -> None:
    f = tmp_path / "app.py"
    f.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )
    findings = [x for x in scan_source_file(f) if x.algorithm == "RSA"]
    assert findings
    assert findings[0].key_size == 4096


def test_config_ed25519_not_grouped_with_chacha(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_text("HostKeyAlgorithms ssh-ed25519\n")
    finding = scan_config_file(f)[0]
    assert finding.algorithm == "Ed25519"
    assert finding.quantum_risk == QuantumRisk.VULNERABLE


def test_wrong_location_scores_zero() -> None:
    root = Path(__file__).resolve().parents[1]
    corpus_dir = root / "data/evaluation/corpus"
    gt_path = root / "data/evaluation/ground_truth.yaml"
    output = scan_evaluation_project(corpus_dir, "proj_rsa_app")
    tampered = [
        CryptoFinding(
            finding_id=f.finding_id,
            source=f.source,
            algorithm=f.algorithm,
            key_size=f.key_size,
            location="nonexistent.py:999",
            evidence="wrong",
            quantum_risk=f.quantum_risk,
            migration_priority=f.migration_priority,
            metadata=dict(f.metadata),
        )
        for f in output.findings
    ]
    predicted = {evaluation_key("proj_rsa_app", f) for f in tampered}
    from pqc_readiness.evaluation.ground_truth import load_ground_truth

    expected = {
        item.item_key
        for item in load_ground_truth(gt_path).items
        if item.project_id == "proj_rsa_app"
    }
    metrics = compute_metrics(predicted, expected)
    assert metrics.f1 == 0.0


def test_pipeline_covers_all_fixture_artifact_classes() -> None:
    root = Path(__file__).resolve().parents[1]
    scan = run_pipeline(
        PipelineConfig(corpus_dir=root / "data/evaluation/corpus", skip_tls=True)
    )
    sources = {f.source.value for f in scan.findings}
    assert {"code", "config", "x509", "ssh"}.issubset(sources)


def test_pipeline_priorities_match_plan() -> None:
    from pqc_readiness.classification.priority import build_migration_plan

    root = Path(__file__).resolve().parents[1]
    scan = run_pipeline(
        PipelineConfig(corpus_dir=root / "data/evaluation/corpus", skip_tls=True)
    )
    plan = build_migration_plan(scan.findings)
    assert sum(plan.summary.values()) == len(scan.findings)
    for action in plan.actions:
        match = next(f for f in scan.findings if f.finding_id == action.finding_id)
        assert match.migration_priority == action.priority


def test_no_absolute_users_paths_in_pipeline_output(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "out"
    config = PipelineConfig(
        corpus_dir=root / "data/evaluation/corpus",
        skip_tls=True,
        output_dir=out,
    )
    from pqc_readiness.pipeline import write_pipeline_outputs

    scan = run_pipeline(config)
    paths = write_pipeline_outputs(scan, config)
    for path in paths.values():
        text = path.read_text(encoding="utf-8")
        assert ("/" + "Users" + "/") not in text


def test_missing_required_input_returns_error() -> None:
    config = PipelineConfig(
        code_dir=Path("definitely-missing-code-dir"),
        skip_tls=True,
        require_inputs=True,
    )
    scan = run_pipeline(config)
    assert scan.errors


def test_cbom_schema_validation() -> None:
    root = Path(__file__).resolve().parents[1]
    schema_path = root / "data" / "schemas" / "bom-1.6.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not vendored")
    import jsonschema

    scan = ScanResult(
        findings=[
            CryptoFinding(
                finding_id="f1",
                source=EvidenceSource.CODE,
                algorithm="RSA",
                key_size=2048,
                location="data/app.py:1",
                evidence="rsa",
                quantum_risk=QuantumRisk.VULNERABLE,
                migration_priority=MigrationPriority.HIGH,
            )
        ]
    )
    cbom = build_cbom(scan)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(cbom, schema)


def test_regenerate_results_script_ruff_clean() -> None:
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "scripts", "data"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
