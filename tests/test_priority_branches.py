"""Priority scoring branch coverage."""

from pqc_readiness.classification.priority import build_migration_plan, score_migration_priority
from pqc_readiness.models import (
    CryptoFinding,
    EvidenceSource,
    MigrationPriority,
    QuantumRisk,
    SensitivityClass,
)


def test_score_low_and_medium() -> None:
    low = score_migration_priority(
        QuantumRisk.REDUCED,
        SensitivityClass.PUBLIC,
        lifetime_years=1,
        harvest_exposure=False,
    )
    assert low in (MigrationPriority.LOW, MigrationPriority.MEDIUM, MigrationPriority.MONITOR)


def test_plan_action_text() -> None:
    finding = CryptoFinding(
        finding_id="rsa1",
        source=EvidenceSource.CODE,
        algorithm="RSA",
        key_size=2048,
        location="a.py:1",
        evidence="rsa",
        quantum_risk=QuantumRisk.VULNERABLE,
        migration_priority=MigrationPriority.HIGH,
    )
    plan = build_migration_plan([finding])
    assert plan.actions
    assert "ML-KEM" in plan.actions[0].action


def test_plan_skips_monitor() -> None:
    finding = CryptoFinding(
        finding_id="safe1",
        source=EvidenceSource.CODE,
        algorithm="ML-KEM",
        key_size=768,
        location="a.py:1",
        evidence="ml-kem",
        quantum_risk=QuantumRisk.SAFE,
        migration_priority=MigrationPriority.MONITOR,
    )
    plan = build_migration_plan([finding])
    assert plan.actions == []
