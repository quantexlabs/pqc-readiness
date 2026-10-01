"""Module entry and CBOM edge cases."""

import runpy
import sys
from io import StringIO
from pathlib import Path

import pytest

from pqc_readiness.cbom.builder import finding_to_component
from pqc_readiness.models import (
    CryptoFinding,
    EvidenceSource,
    MigrationPriority,
    QuantumRisk,
)


def test_cbom_reduced_risk() -> None:
    finding = CryptoFinding(
        finding_id="x-reduced",
        source=EvidenceSource.TLS,
        algorithm="AES-128",
        key_size=128,
        location="t",
        evidence="e",
        quantum_risk=QuantumRisk.REDUCED,
        migration_priority=MigrationPriority.MEDIUM,
    )
    comp = finding_to_component(finding)
    assert "nistQuantumSecurityLevel" not in comp["cryptoProperties"]["algorithmProperties"]


def test_cbom_unknown_risk() -> None:
    finding = CryptoFinding(
        finding_id="x-unknown",
        source=EvidenceSource.TLS,
        algorithm="MYALG",
        key_size=None,
        location="t",
        evidence="e",
        quantum_risk=QuantumRisk.UNKNOWN,
        migration_priority=MigrationPriority.MEDIUM,
    )
    comp = finding_to_component(finding)
    assert "nistQuantumSecurityLevel" not in comp["cryptoProperties"]["algorithmProperties"]


def test_main_module(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "pqc-readiness",
            "evaluate",
            "--n-bootstrap",
            "10",
            "--output",
            str(tmp_path / "evaluation.json"),
        ],
    )
    buf = StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("pqc_readiness.__main__", run_name="__main__")
    assert exc.value.code == 0
