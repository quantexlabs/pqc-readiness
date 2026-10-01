"""Shared constants aligned with NIST PQC and CCCS ITSM.40.001 milestones."""

from __future__ import annotations

from datetime import date

# NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) algorithm families
PQC_ALGORITHMS: frozenset[str] = frozenset(
    {
        "ML-KEM",
        "ML-DSA",
        "SLH-DSA",
        "KYBER",
        "DILITHIUM",
        "SPHINCS",
        "FALCON",
    }
)

# Algorithms vulnerable to Shor's algorithm on a cryptographically relevant quantum computer
QUANTUM_VULNERABLE_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RSA",
        "DSA",
        "ECDSA",
        "ECDH",
        "DH",
        "EC",
        "DIFFIE-HELLMAN",
        "ELGAMAL",
        "ED25519",
        "ED448",
        "EDDSA",
        "X25519",
        "X448",
    }
)

HASH_ALGORITHM_ALIASES: dict[str, str] = {
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA1": "SHA-1",
    "SHA-1": "SHA-1",
    "SHA-256": "SHA-256",
    "SHA-384": "SHA-384",
    "SHA-512": "SHA-512",
}

# Symmetric algorithms with reduced security margin under Grover (not Shor-vulnerable)
GROVER_AFFECTED: frozenset[str] = frozenset({"AES-128", "SHA-256", "HMAC-SHA256"})

# CCCS ITSM.40.001 milestones (Government of Canada PQC roadmap)
CCCS_MILESTONES: dict[str, date] = {
    "initial_plan": date(2026, 4, 1),
    "high_priority_complete": date(2031, 12, 31),
    "remaining_complete": date(2035, 12, 31),
}

# Default public TLS test hosts (explicitly intended for TLS testing)
DEFAULT_TLS_TEST_HOSTS: tuple[str, ...] = (
    "badssl.com",
    "tls-v1-2.badssl.com",
    "self-signed.badssl.com",
    "rsa2048.badssl.com",
    "rsa4096.badssl.com",
    "ecc256.badssl.com",
)

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_REPO_FILES = 5000
TLS_TIMEOUT_SECONDS = 10.0
MAX_TLS_HOSTS = 50
