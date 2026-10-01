"""Typed domain models for cryptographic findings and migration planning."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from typing import Any

from pqc_readiness.coverage import ScanCoverage


def _empty_metadata() -> dict[str, Any]:
    return {}


def _empty_findings() -> list[CryptoFinding]:
    return []


def _empty_str_list() -> list[str]:
    return []


def _empty_actions() -> list[MigrationAction]:
    return []


def _empty_summary() -> dict[str, int]:
    return {}


class EvidenceSource(StrEnum):
    """Where a finding was observed."""

    TLS = "tls"
    X509 = "x509"
    SSH = "ssh"
    CODE = "code"
    CONFIG = "config"


class QuantumRisk(StrEnum):
    """Quantum threat classification."""

    VULNERABLE = "vulnerable"  # Shor-affected public-key crypto
    REDUCED = "reduced"  # Grover-affected symmetric margin
    SAFE = "safe"  # PQC or adequate symmetric strength
    UNKNOWN = "unknown"


class MigrationPriority(StrEnum):
    """Priority band aligned with ITSM.40.001 high-priority vs remaining systems."""

    CRITICAL = "critical"  # harvest-now-decrypt-later, long-lived secrets
    HIGH = "high"  # due before 2031 milestone
    MEDIUM = "medium"
    LOW = "low"
    MONITOR = "monitor"


class SensitivityClass(StrEnum):
    """Data sensitivity for priority scoring."""

    PROTECTED_B = "protected_b"
    PROTECTED_A = "protected_a"
    UNCLASSIFIED = "unclassified"
    PUBLIC = "public"


@dataclass(frozen=True)
class CryptoFinding:
    """A single cryptographic asset observation."""

    finding_id: str
    source: EvidenceSource
    algorithm: str
    key_size: int | None
    location: str
    evidence: str
    quantum_risk: QuantumRisk
    migration_priority: MigrationPriority
    metadata: dict[str, Any] = field(default_factory=_empty_metadata)

    def unique_key(self) -> str:
        """Stable key for evaluation matching."""
        return self.finding_id


@dataclass
class ScanResult:
    """Aggregated scan output."""

    findings: list[CryptoFinding] = field(default_factory=_empty_findings)
    errors: list[str] = field(default_factory=_empty_str_list)
    scan_targets: list[str] = field(default_factory=_empty_str_list)
    warnings: list[str] = field(default_factory=_empty_str_list)
    coverage: ScanCoverage = field(default_factory=ScanCoverage)

    def add(self, finding: CryptoFinding) -> None:
        self.findings.append(finding)


@dataclass(frozen=True)
class MigrationAction:
    """One recommended migration step."""

    finding_id: str
    action: str
    target_milestone: date
    rationale: str
    priority: MigrationPriority


@dataclass
class MigrationPlan:
    """Roadmap-aligned migration plan."""

    actions: list[MigrationAction] = field(default_factory=_empty_actions)
    summary: dict[str, int] = field(default_factory=_empty_summary)
    reference: str = "CCCS ITSM.40.001"
