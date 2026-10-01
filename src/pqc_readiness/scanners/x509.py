"""X.509 certificate parser."""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqc_readiness.classification.priority import classify_quantum_risk, normalize_algorithm
from pqc_readiness.findings import default_scanner_priority
from pqc_readiness.models import CryptoFinding, EvidenceSource
from pqc_readiness.paths import format_location, make_finding_id


def findings_from_certificate(cert: x509.Certificate, location: str) -> list[CryptoFinding]:
    """Extract cryptographic findings from an X.509 certificate."""
    findings: list[CryptoFinding] = []
    pub = cert.public_key()
    key_size: int | None = None
    algo = "UNKNOWN"

    if isinstance(pub, rsa.RSAPublicKey):
        algo = "RSA"
        key_size = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        algo = f"EC-{pub.curve.name}"
        key_size = pub.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        algo = "DSA"
        key_size = pub.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        algo = "Ed25519"
        key_size = 256
    elif isinstance(pub, ed448.Ed448PublicKey):
        algo = "Ed448"
        key_size = 456

    risk = classify_quantum_risk(algo, key_size)
    findings.append(
        CryptoFinding(
            finding_id=make_finding_id("x509-pub", location, algo, str(key_size)),
            source=EvidenceSource.X509,
            algorithm=algo,
            key_size=key_size,
            location=location,
            evidence=f"Subject public key {algo} size={key_size}",
            quantum_risk=risk,
            migration_priority=default_scanner_priority(risk),
            metadata={
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "observation": "parsed_certificate",
                "use": "unknown",
            },
        )
    )

    sig_name = normalize_algorithm(cert.signature_algorithm_oid._name)
    sig_risk = classify_quantum_risk(sig_name, key_size)
    findings.append(
        CryptoFinding(
            finding_id=make_finding_id("x509-sig", location, sig_name),
            source=EvidenceSource.X509,
            algorithm=sig_name,
            key_size=None,
            location=f"{location}/signature",
            evidence=f"Signature algorithm {sig_name}",
            metadata={
                "use": "signature",
                "observation": "parsed_certificate",
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
            },
            quantum_risk=sig_risk,
            migration_priority=default_scanner_priority(sig_risk),
        )
    )
    return findings


def scan_x509_file(
    path: str,
    *,
    scan_root: Path | None = None,
    namespace: str = "",
) -> list[CryptoFinding]:
    """Load a PEM or DER certificate file."""
    cert_path = Path(path)
    data = cert_path.read_bytes()
    if b"-----BEGIN" in data:
        cert = x509.load_pem_x509_certificate(data)
    else:
        cert = x509.load_der_x509_certificate(data)
    return findings_from_certificate(
        cert, location=format_location(cert_path, scan_root=scan_root, namespace=namespace)
    )
