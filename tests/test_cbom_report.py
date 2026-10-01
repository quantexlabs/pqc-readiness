import json

from pqc_readiness.cbom.builder import build_cbom
from pqc_readiness.classification.priority import build_migration_plan
from pqc_readiness.models import (
    CryptoFinding,
    EvidenceSource,
    MigrationPriority,
    QuantumRisk,
    ScanResult,
)
from pqc_readiness.report.html import escape, render_report


def test_build_cbom() -> None:
    scan = ScanResult(
        findings=[
            CryptoFinding(
                finding_id="f1",
                source=EvidenceSource.CODE,
                algorithm="RSA",
                key_size=2048,
                location="a.py:1",
                evidence="rsa",
                quantum_risk=QuantumRisk.VULNERABLE,
                migration_priority=MigrationPriority.HIGH,
            )
        ]
    )
    cbom = build_cbom(scan)
    assert cbom["bomFormat"] == "CycloneDX"
    assert len(cbom["components"]) == 1


def test_html_escape() -> None:
    assert "&lt;" in escape("<script>")


def test_render_report() -> None:
    scan = ScanResult(findings=[], errors=[], scan_targets=["local"])
    plan = build_migration_plan([])
    html = render_report(scan, plan, json.loads(json.dumps(build_cbom(scan))))
    assert "<h1>" in html
    assert "main" in html
