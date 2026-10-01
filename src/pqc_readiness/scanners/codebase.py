"""Source code cryptographic usage scanner."""

from __future__ import annotations

import re
from pathlib import Path

from pqc_readiness.classification.priority import classify_quantum_risk, normalize_algorithm
from pqc_readiness.constants import MAX_FILE_BYTES, MAX_REPO_FILES
from pqc_readiness.coverage import ScanCoverage
from pqc_readiness.findings import default_scanner_priority
from pqc_readiness.models import CryptoFinding, EvidenceSource, QuantumRisk
from pqc_readiness.paths import find_repo_root, format_location, make_finding_id
from pqc_readiness.security import safe_read_text

CODE_EXTENSIONS = frozenset(
    {".py", ".java", ".js", ".ts", ".go", ".rs", ".c", ".cpp", ".h", ".cs"}
)

_SKIP_FILENAMES = frozenset({"_gen_cert.py"})

_PATTERNS: list[tuple[re.Pattern[str], str, int | None, bool]] = [
    (re.compile(r"\bRSA\.generate\s*\(\s*(\d+)", re.I), "RSA", None, False),
    (
        re.compile(r"\brsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(\d+)", re.I),
        "RSA",
        None,
        False,
    ),
    (re.compile(r"\bRSA\.(generate_private_key|generate_key)\b", re.I), "RSA", None, False),
    (re.compile(r"rsa\.generate_private_key\s*\(", re.I), "RSA", None, False),
    (re.compile(r"\bEC\.generate\s*\(", re.I), "EC", None, False),
    (re.compile(r"EllipticCurvePublicKey|ECDSA|secp256r1|prime256v1", re.I), "ECDSA", None, False),
    (re.compile(r"\bDSA\.generate\s*\(\s*(\d+)", re.I), "DSA", None, False),
    (re.compile(r"AES\.new\s*\([^)]*AES\.(MODE_[A-Z0-9_]+)", re.I), "AES", None, False),
    (re.compile(r"\bChaCha20\b", re.I), "ChaCha20", 256, False),
    (re.compile(r"\bhashlib\.(md5|sha1|sha256|sha384|sha512)\b", re.I), "HASH", None, False),
    (re.compile(r"\bMD5\b", re.I), "MD5", None, False),
    (re.compile(r"\bSHA1\b|\bSHA-1\b", re.I), "SHA-1", None, False),
    (re.compile(r"ML-KEM|ML_KEM|Kyber|kyber", re.I), "ML-KEM", None, True),
    (re.compile(r"ML-DSA|ML_DSA|Dilithium|dilithium", re.I), "ML-DSA", None, True),
    (re.compile(r"SLH-DSA|SPHINCS|sphincs", re.I), "SLH-DSA", None, True),
    (re.compile(r"DiffieHellman|DHParameter|ECDH|X25519", re.I), "ECDH", None, False),
    (re.compile(r"PBKDF2|scrypt|argon2", re.I), "KDF", None, False),
]


def _extract_key_size(match: re.Match[str], pattern_idx: int) -> int | None:
    pattern = _PATTERNS[pattern_idx]
    if pattern[1] == "RSA" and match.lastindex:
        try:
            return int(match.group(1))
        except (IndexError, ValueError):
            return None
    if pattern[1] == "DSA" and match.lastindex:
        try:
            return int(match.group(1))
        except (IndexError, ValueError):
            return None
    return pattern[2]


def scan_source_file(
    path: Path,
    *,
    scan_root: Path | None = None,
    namespace: str = "",
) -> list[CryptoFinding]:
    """Scan one source file for cryptographic patterns."""
    if path.name in _SKIP_FILENAMES or path.name.startswith("_"):
        return []
    if path.suffix.lower() not in CODE_EXTENSIONS:
        return []
    if path.stat().st_size > MAX_FILE_BYTES:
        return []
    text = safe_read_text(path)
    findings: list[CryptoFinding] = []
    location_base = format_location(path, scan_root=scan_root, namespace=namespace)
    seen_lines: set[tuple[int, str]] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        for idx, (pattern, algo, default_size, lexical_only) in enumerate(_PATTERNS):
            match = pattern.search(line)
            if not match:
                continue
            if algo == "HASH" and match.lastindex:
                algo = normalize_algorithm(match.group(1))
            dedupe_key = (line_no, algo)
            if dedupe_key in seen_lines:
                continue
            seen_lines.add(dedupe_key)
            key_size = _extract_key_size(match, idx) or default_size
            risk = QuantumRisk.UNKNOWN if lexical_only else classify_quantum_risk(algo, key_size)
            line_evidence = line.strip()[:120]
            metadata: dict[str, object] = {
                "line": line_no,
                "observation": "static_pattern",
                "use": "unknown",
            }
            if lexical_only:
                metadata["observation"] = "lexical_marker"
            findings.append(
                CryptoFinding(
                    finding_id=make_finding_id("code", location_base, str(line_no), algo),
                    source=EvidenceSource.CODE,
                    algorithm=algo,
                    key_size=key_size,
                    location=format_location(
                        path, line_no, scan_root=scan_root, namespace=namespace
                    ),
                    evidence=line_evidence,
                    quantum_risk=risk,
                    migration_priority=default_scanner_priority(risk),
                    metadata=metadata,
                )
            )
    return findings


def scan_code_directory(
    root: Path,
    max_files: int = MAX_REPO_FILES,
    coverage: ScanCoverage | None = None,
    *,
    scan_root: Path | None = None,
    namespace: str = "",
    errors: list[str] | None = None,
) -> list[CryptoFinding]:
    """Walk a directory and scan source files with a file count cap."""
    findings: list[CryptoFinding] = []
    count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        if path.name in _SKIP_FILENAMES or path.name.startswith("_"):
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
            observations = scan_source_file(path, scan_root=location_root, namespace=namespace)
        except (OSError, ValueError) as exc:
            location = format_location(path, scan_root=location_root, namespace=namespace)
            if coverage is not None:
                coverage.add_failed(location, type(exc).__name__)
            if errors is not None:
                errors.append(f"Failed code file: {location} ({type(exc).__name__})")
            continue
        if coverage is not None:
            coverage.files_scanned += 1
        findings.extend(observations)
    return findings
