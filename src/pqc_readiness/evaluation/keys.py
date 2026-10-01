"""Stable evaluation key generation."""

from __future__ import annotations

from pqc_readiness.models import CryptoFinding
from pqc_readiness.paths import stable_digest


def evaluation_key(project_id: str, finding: CryptoFinding) -> str:
    """Stable evaluation key aligned with ground truth authoring."""
    location = finding.location
    if finding.source.value == "ssh" and ":" not in location:
        line = str(finding.metadata.get("line", ""))
        if line:
            location = f"{location}:{line}"
    digest = stable_digest(
        project_id,
        finding.source.value,
        finding.algorithm.upper(),
        location,
        length=20,
    )
    return f"{project_id}:{digest}"
