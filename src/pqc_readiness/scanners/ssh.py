"""SSH host key scanner."""

from __future__ import annotations

import base64
import re
from pathlib import Path

from pqc_readiness.classification.priority import classify_quantum_risk
from pqc_readiness.findings import default_scanner_priority
from pqc_readiness.models import CryptoFinding, EvidenceSource
from pqc_readiness.paths import format_location, make_finding_id
from pqc_readiness.security import safe_read_text

_SSH_KEY_LINE = re.compile(
    r"^(?P<algo>[a-z0-9-]+)\s+(?P<key>[A-Za-z0-9+/=]+)(?:\s+(?P<comment>.*))?$"
)

_ALGO_MAP = {
    "ssh-rsa": ("RSA", None),
    "rsa-sha2-256": ("RSA", None),
    "rsa-sha2-512": ("RSA", None),
    "ecdsa-sha2-nistp256": ("EC-P256", 256),
    "ecdsa-sha2-nistp384": ("EC-P384", 384),
    "ecdsa-sha2-nistp521": ("EC-P521", 521),
    "ssh-ed25519": ("Ed25519", 256),
    "ssh-dss": ("DSA", None),
}


def parse_ssh_known_hosts_line(line: str, file_location: str, line_no: int) -> CryptoFinding | None:
    """Parse one line from known_hosts format."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split()
    if len(parts) < 3:
        return None
    host_part, algo, key_b64 = parts[0], parts[1], parts[2]
    mapped = _ALGO_MAP.get(algo)
    if not mapped:
        mapped_algo = algo.upper()
        key_size = None
    else:
        mapped_algo, key_size = mapped
    risk = classify_quantum_risk(mapped_algo, key_size)
    key_preview = base64.b64decode(key_b64[:40] + "==", validate=False)[:8].hex()
    return CryptoFinding(
        finding_id=make_finding_id(
            "ssh", file_location, str(line_no), host_part, algo, key_preview
        ),
        source=EvidenceSource.SSH,
        algorithm=mapped_algo,
        key_size=key_size,
        location=f"{file_location}:{line_no}",
        evidence=f"SSH host key algorithm {algo} for host marker {host_part}",
        quantum_risk=risk,
        migration_priority=default_scanner_priority(risk),
        metadata={
            "ssh_algorithm": algo,
            "host": host_part,
            "line": line_no,
            "use": "signature",
            "observation": "parsed_marker",
        },
    )


def scan_ssh_known_hosts(
    path: str | Path,
    *,
    scan_root: Path | None = None,
    namespace: str = "",
) -> list[CryptoFinding]:
    """Scan an SSH known_hosts file."""
    ssh_path = Path(path)
    text = safe_read_text(ssh_path)
    findings: list[CryptoFinding] = []
    loc = format_location(ssh_path, scan_root=scan_root, namespace=namespace)
    for line_no, line in enumerate(text.splitlines(), start=1):
        finding = parse_ssh_known_hosts_line(line, loc, line_no)
        if finding:
            findings.append(finding)
    return findings


def scan_ssh_public_key_line(line: str, location: str = "inline") -> CryptoFinding | None:
    """Parse a single SSH public key line."""
    match = _SSH_KEY_LINE.match(line.strip())
    if not match:
        return None
    algo = match.group("algo")
    mapped = _ALGO_MAP.get(algo, (algo.upper(), None))
    mapped_algo, key_size = mapped
    risk = classify_quantum_risk(mapped_algo, key_size)
    return CryptoFinding(
        finding_id=make_finding_id("ssh-pub", location, algo),
        source=EvidenceSource.SSH,
        algorithm=mapped_algo,
        key_size=key_size,
        location=location,
        evidence=f"SSH public key type {algo}",
        quantum_risk=risk,
        migration_priority=default_scanner_priority(risk),
        metadata={"ssh_algorithm": algo},
    )
