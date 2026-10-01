"""Additional coverage for classification and security edge cases."""

from pathlib import Path

import pytest

from pqc_readiness.classification.priority import (
    classify_quantum_risk,
    score_migration_priority,
)
from pqc_readiness.constants import CCCS_MILESTONES
from pqc_readiness.models import MigrationPriority, QuantumRisk, SensitivityClass
from pqc_readiness.security import safe_read_text, validate_host


def test_normalize_and_unknown_risk() -> None:
    assert classify_quantum_risk("CUSTOM-ALGO") == QuantumRisk.UNKNOWN


def test_score_monitor_for_safe() -> None:
    assert (
        score_migration_priority(
            QuantumRisk.SAFE,
            SensitivityClass.PUBLIC,
            lifetime_years=1,
            harvest_exposure=False,
        )
        == MigrationPriority.MONITOR
    )


def test_cccs_milestones_present() -> None:
    assert CCCS_MILESTONES["initial_plan"].year == 2026


def test_safe_read_text_too_large(tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_text("x" * 100)
    from pqc_readiness.constants import MAX_FILE_BYTES

    huge = tmp_path / "huge.txt"
    huge.write_bytes(b"a" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError):
        safe_read_text(huge)


def test_validate_host_invalid() -> None:
    with pytest.raises(ValueError):
        validate_host("")
