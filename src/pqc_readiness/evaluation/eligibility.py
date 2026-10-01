"""Shared eligible inputs for the two fixture regression systems."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from pqc_readiness.constants import MAX_FILE_BYTES, MAX_REPO_FILES
from pqc_readiness.models import EvidenceSource
from pqc_readiness.scanners.codebase import CODE_EXTENSIONS
from pqc_readiness.scanners.config import CONFIG_EXTENSIONS, CONFIG_NAMES


def eligible_project_files(project: Path) -> Iterator[tuple[Path, EvidenceSource]]:
    """Apply the same artifact paths, exclusions and caps before either detector runs."""
    for directory, source in (("src", EvidenceSource.CODE), ("config", EvidenceSource.CONFIG)):
        count = 0
        for path in sorted((project / directory).rglob("*")):
            if not path.is_file():
                continue
            if source == EvidenceSource.CODE:
                if path.name.startswith("_") or path.suffix.lower() not in CODE_EXTENSIONS:
                    continue
            elif path.name not in CONFIG_NAMES and path.suffix.lower() not in CONFIG_EXTENSIONS:
                continue
            count += 1
            if count > MAX_REPO_FILES:
                break
            if path.stat().st_size <= MAX_FILE_BYTES:
                yield path, source
    hosts = project / "ssh/known_hosts"
    if hosts.is_file() and hosts.stat().st_size <= MAX_FILE_BYTES:
        yield hosts, EvidenceSource.SSH
    for path in sorted((project / "certs").glob("*.pem")):
        if not path.name.startswith("_") and path.stat().st_size <= MAX_FILE_BYTES:
            yield path, EvidenceSource.X509
