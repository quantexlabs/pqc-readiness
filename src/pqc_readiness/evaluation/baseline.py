"""Naive regex baseline for evaluation comparison."""

from __future__ import annotations

import re
from pathlib import Path

from pqc_readiness.evaluation.eligibility import eligible_project_files
from pqc_readiness.evaluation.keys import evaluation_key
from pqc_readiness.evaluation.runner import ProjectScanOutput
from pqc_readiness.models import CryptoFinding, MigrationPriority, QuantumRisk
from pqc_readiness.paths import format_location

_SIMPLE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"RSA|rsa", re.I), "RSA"),
    (re.compile(r"ECDSA|ec\.generate|EllipticCurve", re.I), "ECDSA"),
    (re.compile(r"ML-KEM|Kyber", re.I), "ML-KEM"),
    (re.compile(r"ML-DSA|Dilithium", re.I), "ML-DSA"),
    (re.compile(r"ssh-rsa", re.I), "RSA"),
    (re.compile(r"ecdsa-sha2", re.I), "EC-P256"),
    (re.compile(r"ssh-ed25519", re.I), "Ed25519"),
    (re.compile(r"ssl_ciphers", re.I), "TLS-CIPHER"),
]


def baseline_scan_project(corpus_dir: Path, project_id: str) -> ProjectScanOutput:
    """Run minimal regex scan without structured parsers."""
    project_path = corpus_dir / project_id
    findings: list[CryptoFinding] = []
    for path, source in eligible_project_files(project_path):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern, algo in _SIMPLE_PATTERNS:
                if "ssl_ciphers" in line.lower() and algo != "TLS-CIPHER":
                    continue
                if not pattern.search(line):
                    continue
                location = format_location(path, line_no)
                finding = CryptoFinding(
                    finding_id=f"baseline-{project_id}-{line_no}-{algo}",
                    source=source,
                    algorithm=algo,
                    key_size=None,
                    location=location,
                    evidence=line.strip()[:80],
                    quantum_risk=QuantumRisk.UNKNOWN,
                    migration_priority=MigrationPriority.MEDIUM,
                    metadata={"line": line_no},
                )
                findings.append(finding)
    predicted = {evaluation_key(project_id, f) for f in findings}
    return ProjectScanOutput(project_id=project_id, predicted_keys=predicted, findings=findings)
