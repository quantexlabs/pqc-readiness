from pqc_readiness.classification.priority import (
    build_migration_plan,
    classify_quantum_risk,
    normalize_algorithm,
    score_migration_priority,
    target_milestone,
)
from pqc_readiness.models import MigrationPriority, QuantumRisk, SensitivityClass


def test_normalize_algorithm() -> None:
    assert normalize_algorithm("rsa_2048") == "RSA-2048"


def test_classify_pqc_safe() -> None:
    assert classify_quantum_risk("ML-KEM-768") == QuantumRisk.SAFE


def test_classify_rsa_vulnerable() -> None:
    assert classify_quantum_risk("RSA", 2048) == QuantumRisk.VULNERABLE


def test_classify_aes128_reduced() -> None:
    assert classify_quantum_risk("AES-128", 128) == QuantumRisk.REDUCED


def test_score_critical_harvest() -> None:
    p = score_migration_priority(
        QuantumRisk.VULNERABLE,
        SensitivityClass.PROTECTED_B,
        lifetime_years=15,
        harvest_exposure=True,
    )
    assert p == MigrationPriority.CRITICAL


def test_target_milestone_high() -> None:
    d = target_milestone(MigrationPriority.HIGH)
    assert d.year == 2031


def test_build_migration_plan_counts() -> None:
    from pqc_readiness.models import CryptoFinding, EvidenceSource

    finding = CryptoFinding(
        finding_id="t1",
        source=EvidenceSource.CODE,
        algorithm="RSA",
        key_size=2048,
        location="a.py:1",
        evidence="rsa",
        quantum_risk=QuantumRisk.VULNERABLE,
        migration_priority=MigrationPriority.HIGH,
    )
    plan = build_migration_plan([finding])
    assert len(plan.actions) == 1
    assert plan.actions[0].priority in (MigrationPriority.HIGH, MigrationPriority.CRITICAL)
