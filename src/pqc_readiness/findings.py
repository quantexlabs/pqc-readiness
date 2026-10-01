"""Finding normalization, deduplication, and priority assignment."""

from __future__ import annotations

from pqc_readiness.classification.priority import finding_use, score_migration_priority
from pqc_readiness.models import CryptoFinding, MigrationPriority, QuantumRisk, SensitivityClass


def dedupe_findings(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """Remove duplicate observations at the same location with the same algorithm."""
    seen: set[tuple[str, str, str, int | None]] = set()
    unique: list[CryptoFinding] = []
    for finding in findings:
        key = (
            finding.source.value,
            finding.algorithm.upper(),
            finding.location,
            finding.key_size,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def apply_migration_priorities(
    findings: list[CryptoFinding],
    *,
    sensitivity: SensitivityClass,
    lifetime_years: int,
    harvest_exposure: bool,
) -> list[CryptoFinding]:
    """Assign migration priority consistently for inventory and planning."""
    updated: list[CryptoFinding] = []
    for finding in findings:
        priority = score_migration_priority(
            finding.quantum_risk,
            sensitivity,
            lifetime_years,
            harvest_exposure,
            use=finding_use(finding),
        )
        updated.append(
            CryptoFinding(
                finding_id=finding.finding_id,
                source=finding.source,
                algorithm=finding.algorithm,
                key_size=finding.key_size,
                location=finding.location,
                evidence=finding.evidence,
                quantum_risk=finding.quantum_risk,
                migration_priority=priority,
                metadata=dict(finding.metadata),
            )
        )
    return updated


def default_scanner_priority(risk: QuantumRisk) -> MigrationPriority:
    """Scanner-local default before pipeline configuration is applied."""
    return {
        QuantumRisk.VULNERABLE: MigrationPriority.HIGH,
        QuantumRisk.REDUCED: MigrationPriority.MEDIUM,
        QuantumRisk.SAFE: MigrationPriority.MONITOR,
        QuantumRisk.UNKNOWN: MigrationPriority.MEDIUM,
    }[risk]
