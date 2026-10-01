"""TLS endpoint scanner for permitted public test hosts."""

from __future__ import annotations

import hashlib
import socket
import ssl
from typing import Any

from pqc_readiness.classification.priority import classify_quantum_risk
from pqc_readiness.constants import TLS_TIMEOUT_SECONDS
from pqc_readiness.models import CryptoFinding, EvidenceSource, ScanResult
from pqc_readiness.security import validate_host


def _finding_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256(":".join(parts).encode()).hexdigest()[:16]
    return f"{prefix}-{digest}"


def scan_tls_host(host: str, port: int = 443, timeout: float = TLS_TIMEOUT_SECONDS) -> ScanResult:
    """Scan a TLS endpoint and extract certificate and cipher information."""
    result = ScanResult(scan_targets=[f"{host}:{port}"])
    try:
        hostname = validate_host(host)
    except ValueError as exc:
        result.errors.append(f"Invalid host ({type(exc).__name__})")
        return result

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with (
            socket.create_connection((hostname, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as tls,
        ):
            cert_bin = tls.getpeercert(binary_form=True)
            cipher = tls.cipher()
            version = tls.version()
            if cert_bin:
                _add_cert_findings(result, hostname, port, cert_bin, tls.getpeercert())
            if cipher:
                name, proto, bits = cipher
                cipher_risk = classify_quantum_risk(name, bits)
                result.add(
                    CryptoFinding(
                        finding_id=_finding_id("tls-cipher", hostname, name),
                        source=EvidenceSource.TLS,
                        algorithm=name,
                        key_size=bits,
                        location=f"tls://{hostname}:{port}",
                        evidence=(
                            f"Negotiated cipher {name} ({bits} bits), protocol {version}, {proto}"
                        ),
                        metadata={
                            "protocol_version": version or proto,
                            "use": "confidentiality",
                            "observation": "negotiated_cipher",
                        },
                        quantum_risk=cipher_risk,
                        migration_priority=_priority_from_risk(cipher_risk),
                    )
                )
    except (OSError, ValueError) as exc:
        result.errors.append(f"{hostname}:{port}: {type(exc).__name__}")
    return result


def _priority_from_risk(risk: Any) -> Any:
    from pqc_readiness.models import MigrationPriority, QuantumRisk

    mapping = {
        QuantumRisk.VULNERABLE: MigrationPriority.HIGH,
        QuantumRisk.REDUCED: MigrationPriority.MEDIUM,
        QuantumRisk.SAFE: MigrationPriority.MONITOR,
        QuantumRisk.UNKNOWN: MigrationPriority.MEDIUM,
    }
    return mapping[risk]


def _add_cert_findings(
    result: ScanResult,
    host: str,
    port: int,
    cert_bin: bytes,
    cert_dict: dict[str, Any] | None,
) -> None:
    from cryptography import x509

    from pqc_readiness.scanners.x509 import findings_from_certificate

    try:
        cert = x509.load_der_x509_certificate(cert_bin)
    except ValueError:
        result.errors.append("Malformed peer certificate")
        return

    for finding in findings_from_certificate(cert, location=f"tls://{host}:{port}/cert"):
        result.add(finding)

    if cert_dict:
        sig_oid = cert.signature_algorithm_oid._name
        sig_risk = classify_quantum_risk(sig_oid, None)
        result.add(
            CryptoFinding(
                finding_id=_finding_id("tls-sig", host, sig_oid),
                source=EvidenceSource.TLS,
                algorithm=sig_oid,
                key_size=None,
                location=f"tls://{host}:{port}/signature",
                evidence=f"Certificate signature algorithm {sig_oid}",
                quantum_risk=sig_risk,
                migration_priority=_priority_from_risk(sig_risk),
            )
        )
