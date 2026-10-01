"""Schema lineage and offline validation checks for round four."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def staged_validator(tmp_path: Path) -> tuple[Path, Path]:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "data" / "schemas").mkdir(parents=True)
    (tmp_path / "results" / "latest").mkdir(parents=True)
    shutil.copy(ROOT / "scripts" / "validate_schema.py", tmp_path / "scripts")
    for name in (
        "bom-1.6.schema.json",
        "spdx.schema.json",
        "jsf-0.82.schema.json",
        "provenance.json",
    ):
        shutil.copy(ROOT / "data" / "schemas" / name, tmp_path / "data" / "schemas")
    shutil.copy(
        ROOT / "results" / "latest" / "inventory.cbom.json",
        tmp_path / "results" / "latest" / "inventory.cbom.json",
    )
    return tmp_path / "scripts" / "validate_schema.py", tmp_path / "data" / "schemas"


def run_validator(script: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_offline_schema_references_and_fixture(tmp_path: Path) -> None:
    script, _ = staged_validator(tmp_path)
    proc = run_validator(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    receipt = json.loads(proc.stdout)
    assert receipt["external_references"] == ["jsf-0.82.schema.json", "spdx.schema.json"]
    assert receipt["missing_references"] == []
    assert receipt["fixture_errors"] == []


def test_offline_refs_validate_license_and_signature_shapes(tmp_path: Path) -> None:
    script, _ = staged_validator(tmp_path)
    fixture = tmp_path / "results/latest/inventory.cbom.json"
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"licenses": [{"license": {"id": "Apache-2.0"}}]},
        "signature": {"algorithm": "urn:example:synthetic-signature", "value": "c3ludGhldGlj"},
    }
    fixture.write_text(json.dumps(payload))
    valid = run_validator(script)
    assert valid.returncode == 0, valid.stdout + valid.stderr
    # This is JSON shape validation, not a cryptographic signature verification.
    payload["metadata"] = {"licenses": [{"license": {"id": "invalid-synthetic-license"}}]}
    fixture.write_text(json.dumps(payload))
    assert run_validator(script).returncode == 1
    payload["metadata"] = {"licenses": [{"license": {"id": "Apache-2.0"}}]}
    payload["signature"] = {"value": "c3ludGhldGlj"}
    fixture.write_text(json.dumps(payload))
    assert run_validator(script).returncode == 1


def test_schema_validator_rejects_constraint_fingerprint_drift(tmp_path: Path) -> None:
    script, schema_dir = staged_validator(tmp_path)
    provenance_path = schema_dir / "provenance.json"
    provenance = json.loads(provenance_path.read_text())
    provenance["constraint_fingerprint"]["sha256"] = "0" * 64
    provenance_path.write_text(json.dumps(provenance))
    proc = run_validator(script)
    assert proc.returncode == 1
    assert "constraint fingerprint mismatch" in proc.stdout


def test_schema_validator_rejects_derivative_hash_drift(tmp_path: Path) -> None:
    script, schema_dir = staged_validator(tmp_path)
    provenance_path = schema_dir / "provenance.json"
    provenance = json.loads(provenance_path.read_text())
    provenance["derivative_sha256"] = "0" * 64
    provenance_path.write_text(json.dumps(provenance))
    proc = run_validator(script)
    assert proc.returncode == 1
    assert "derivative file hash mismatch" in proc.stdout


def test_schema_validator_reports_missing_external_reference(tmp_path: Path) -> None:
    script, schema_dir = staged_validator(tmp_path)
    (schema_dir / "spdx.schema.json").unlink()
    proc = run_validator(script)
    assert proc.returncode == 1
    receipt = json.loads(proc.stdout)
    assert receipt["missing_references"] == ["spdx.schema.json"]
    assert "external schema reference is not vendored" in receipt["errors"]
