"""Configuration file cryptographic settings scanner."""

from __future__ import annotations

import re
from pathlib import Path

from pqc_readiness.classification.priority import classify_quantum_risk
from pqc_readiness.constants import MAX_FILE_BYTES, MAX_REPO_FILES
from pqc_readiness.coverage import ScanCoverage
from pqc_readiness.findings import default_scanner_priority
from pqc_readiness.models import CryptoFinding, EvidenceSource, QuantumRisk
from pqc_readiness.paths import find_repo_root, format_location, make_finding_id
from pqc_readiness.security import safe_read_text

CONFIG_NAMES = frozenset(
    {
        "nginx.conf",
        "httpd.conf",
        "apache2.conf",
        "sshd_config",
        "openssl.cnf",
        "security.properties",
    }
)
CONFIG_EXTENSIONS = frozenset({".conf", ".cfg", ".ini", ".yaml", ".yml", ".properties", ".toml"})

_PATTERNS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"ssl_protocols\s+([^;]+)", re.I), "TLS", 1),
    (re.compile(r"ssl_ciphers\s+([^;]+)", re.I), "TLS-CIPHER", 1),
    (re.compile(r"(TLSv1\.[012])", re.I), "TLS-VERSION", 1),
    (re.compile(r"KEXAlgorithms\s+(.+)", re.I), "SSH-KEX", 1),
    (re.compile(r"HostKeyAlgorithms\s+(.+)", re.I), "SSH-HOSTKEY", 1),
    (re.compile(r"\bCiphers\s+(.+)", re.I), "SSH-CIPHER", 1),
    (re.compile(r"MinProtocol\s+(\S+)", re.I), "MIN-PROTOCOL", 1),
]


def _classify_config_value(category: str, value: str) -> tuple[str, QuantumRisk]:
    upper = value.upper()
    if "RSA" in upper or "ECDSA" in upper or "ECDH" in upper:
        return ("RSA/EC", QuantumRisk.VULNERABLE)
    if "ED25519" in upper or "ED448" in upper:
        algo = "Ed25519" if "ED25519" in upper else "Ed448"
        return (algo, QuantumRisk.VULNERABLE)
    if "TLSV1.0" in upper or "TLSV1.1" in upper or "SSLV" in upper:
        return ("TLS-LEGACY", QuantumRisk.VULNERABLE)
    if "AES128" in upper or "AES-128" in upper:
        return ("AES-128", QuantumRisk.REDUCED)
    if "ML-KEM" in upper or "KYBER" in upper:
        return ("ML-KEM", QuantumRisk.UNKNOWN)
    if "CHACHA" in upper:
        return ("ChaCha20", QuantumRisk.UNKNOWN)
    return (category, classify_quantum_risk(category))


def scan_config_file(
    path: Path,
    *,
    scan_root: Path | None = None,
    namespace: str = "",
) -> list[CryptoFinding]:
    """Scan a configuration file for crypto-related directives."""
    if path.stat().st_size > MAX_FILE_BYTES:
        return []
    if path.name not in CONFIG_NAMES and path.suffix.lower() not in CONFIG_EXTENSIONS:
        return []
    text = safe_read_text(path)
    findings: list[CryptoFinding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pattern, category, group in _PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(group).strip()
            algo, risk = _classify_config_value(category, value)
            # A configured name is not evidence of an operative safe algorithm.
            # Apply the observation ceiling before neutral display vocabulary.
            if risk == QuantumRisk.SAFE:
                risk = QuantumRisk.UNKNOWN
            if category == "TLS-CIPHER":
                algo = "TLS-CIPHER"
            findings.append(
                CryptoFinding(
                    finding_id=make_finding_id(
                        "cfg",
                        format_location(path, scan_root=scan_root, namespace=namespace),
                        str(line_no),
                        category,
                    ),
                    source=EvidenceSource.CONFIG,
                    algorithm=algo,
                    key_size=None,
                    location=format_location(
                        path, line_no, scan_root=scan_root, namespace=namespace
                    ),
                    evidence=stripped[:160],
                    quantum_risk=risk,
                    migration_priority=default_scanner_priority(risk),
                    metadata={
                        "directive": category,
                        "value": value[:200],
                        "observation": "configuration_directive",
                        "use": "unknown",
                    },
                )
            )
    return findings


def scan_config_directory(
    root: Path,
    max_files: int = MAX_REPO_FILES,
    coverage: ScanCoverage | None = None,
    *,
    scan_root: Path | None = None,
    namespace: str = "",
    errors: list[str] | None = None,
) -> list[CryptoFinding]:
    """Scan configuration files under a directory."""
    findings: list[CryptoFinding] = []
    count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name not in CONFIG_NAMES and path.suffix.lower() not in CONFIG_EXTENSIONS:
            continue
        count += 1
        if count > max_files:
            if coverage is not None:
                coverage.files_truncated_cap += 1
            continue
        location_root = scan_root or find_repo_root(root)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                if coverage is not None:
                    coverage.files_skipped_size += 1
                continue
            observations = scan_config_file(path, scan_root=location_root, namespace=namespace)
        except (OSError, ValueError) as exc:
            location = format_location(path, scan_root=location_root, namespace=namespace)
            if coverage is not None:
                coverage.add_failed(location, type(exc).__name__)
            if errors is not None:
                errors.append(f"Failed config file: {location} ({type(exc).__name__})")
            continue
        if coverage is not None:
            coverage.files_scanned += 1
        findings.extend(observations)
    return findings
