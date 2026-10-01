"""Quantum vulnerability and migration priority classification."""

from __future__ import annotations

from datetime import date

from pqc_readiness.constants import (
    CCCS_MILESTONES,
    GROVER_AFFECTED,
    HASH_ALGORITHM_ALIASES,
    PQC_ALGORITHMS,
    QUANTUM_VULNERABLE_ALGORITHMS,
)
from pqc_readiness.models import (
    CryptoFinding,
    MigrationAction,
    MigrationPlan,
    MigrationPriority,
    QuantumRisk,
    SensitivityClass,
)


def normalize_algorithm(name: str) -> str:
    """Normalize algorithm name for lookup."""
    cleaned = name.strip().upper().replace("_", "-").replace(" ", "-")
    return HASH_ALGORITHM_ALIASES.get(cleaned, cleaned)


def classify_quantum_risk(algorithm: str, key_size: int | None = None) -> QuantumRisk:
    """Classify quantum vulnerability for an algorithm."""
    norm = normalize_algorithm(algorithm)
    for pqc in PQC_ALGORITHMS:
        if pqc in norm:
            return QuantumRisk.SAFE
    for vuln in QUANTUM_VULNERABLE_ALGORITHMS:
        if vuln in norm or norm.startswith(vuln):
            return QuantumRisk.VULNERABLE
    for sym in GROVER_AFFECTED:
        if sym in norm:
            if "AES-128" in norm or (key_size is not None and key_size <= 128):
                return QuantumRisk.REDUCED
            return QuantumRisk.SAFE
    if norm in {"SHA-256", "SHA-384", "SHA-512"}:
        return QuantumRisk.SAFE
    if norm == "AES":
        if key_size is not None and key_size <= 128:
            return QuantumRisk.REDUCED
        if key_size is not None and key_size > 128:
            return QuantumRisk.SAFE
        return QuantumRisk.UNKNOWN
    if "CHACHA" in norm:
        return QuantumRisk.SAFE
    if "SHA3" in norm:
        return QuantumRisk.SAFE
    return QuantumRisk.UNKNOWN


def score_migration_priority(
    quantum_risk: QuantumRisk,
    sensitivity: SensitivityClass,
    lifetime_years: int,
    harvest_exposure: bool,
    *,
    is_signature_use: bool | None = None,
    use: str | None = None,
) -> MigrationPriority:
    """Score migration priority using harvest-now-decrypt-later and sensitivity."""
    if quantum_risk == QuantumRisk.SAFE:
        return MigrationPriority.MONITOR
    if quantum_risk == QuantumRisk.UNKNOWN:
        return MigrationPriority.MEDIUM

    score = 0
    if quantum_risk == QuantumRisk.VULNERABLE:
        score += 3
    elif quantum_risk == QuantumRisk.REDUCED:
        score += 1

    resolved_use = use or (
        "unknown"
        if is_signature_use is None
        else "signature"
        if is_signature_use
        else "confidentiality"
    )
    if harvest_exposure and resolved_use in {"confidentiality", "key_establishment"}:
        score += 3
    if lifetime_years >= 10:
        score += 2
    elif lifetime_years >= 5:
        score += 1

    if sensitivity == SensitivityClass.PROTECTED_B:
        score += 3
    elif sensitivity == SensitivityClass.PROTECTED_A:
        score += 2
    elif sensitivity == SensitivityClass.UNCLASSIFIED:
        score += 1

    if score >= 7:
        return MigrationPriority.CRITICAL
    if score >= 5:
        return MigrationPriority.HIGH
    if score >= 3:
        return MigrationPriority.MEDIUM
    return MigrationPriority.LOW


def target_milestone(priority: MigrationPriority) -> date:
    """Map priority to CCCS milestone date."""
    if priority in (MigrationPriority.CRITICAL, MigrationPriority.HIGH):
        return CCCS_MILESTONES["high_priority_complete"]
    return CCCS_MILESTONES["remaining_complete"]


def finding_use(finding: CryptoFinding) -> str:
    """Use is an observation, never inferred from an ambiguous key algorithm."""
    use = str(finding.metadata.get("use", "unknown"))
    return use if use in {"signature", "confidentiality", "key_establishment"} else "unknown"


def is_signature_finding(finding: CryptoFinding) -> bool:
    return finding_use(finding) == "signature"


def build_migration_plan(
    findings: list[CryptoFinding],
    sensitivity: SensitivityClass = SensitivityClass.UNCLASSIFIED,
    default_lifetime_years: int = 10,
    harvest_exposure: bool = True,
) -> MigrationPlan:
    """Build a migration plan from findings aligned with ITSM.40.001."""
    actions: list[MigrationAction] = []
    summary: dict[str, int] = {p.value: 0 for p in MigrationPriority}

    for finding in findings:
        priority = score_migration_priority(
            finding.quantum_risk,
            sensitivity,
            default_lifetime_years,
            harvest_exposure,
            use=finding_use(finding),
        )
        summary[priority.value] += 1
        if priority == MigrationPriority.MONITOR:
            continue
        milestone = target_milestone(priority)
        action_text = (
            "Verify observation, parameters and operational use with the asset owner"
            if finding.quantum_risk == QuantumRisk.UNKNOWN
            else _recommendation(finding.algorithm, finding.quantum_risk)
        )
        actions.append(
            MigrationAction(
                finding_id=finding.finding_id,
                action=action_text,
                target_milestone=milestone,
                rationale=(
                    f"Quantum risk {finding.quantum_risk.value}; "
                    f"sensitivity {sensitivity.value}; "
                    f"lifetime {default_lifetime_years}y; "
                    f"harvest exposure {harvest_exposure}; use {finding_use(finding)}; "
                    f"observation {finding.metadata.get('observation', 'unknown')}; "
                    "unvalidated heuristic; asset owner to verify vendor dependencies"
                ),
                priority=priority,
            )
        )

    actions.sort(key=lambda a: (a.target_milestone, a.priority.value, a.finding_id))
    return MigrationPlan(actions=actions, summary=summary)


def _recommendation(algorithm: str, risk: QuantumRisk) -> str:
    norm = normalize_algorithm(algorithm)
    if risk == QuantumRisk.VULNERABLE:
        if "RSA" in norm or "EC" in norm or "DH" in norm or "ED" in norm:
            return (
                "Replace with ML-KEM (FIPS 203) for key exchange "
                "and ML-DSA (FIPS 204) for signatures"
            )
        return "Migrate to NIST-standardized PQC algorithms (FIPS 203/204/205)"
    if risk == QuantumRisk.REDUCED:
        return "Upgrade to AES-256 or SHA-384 minimum symmetric strength"
    return "Monitor for vendor PQC roadmap updates"
