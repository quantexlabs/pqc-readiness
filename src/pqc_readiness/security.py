"""Path and URL validation utilities."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from pqc_readiness.constants import MAX_FILE_BYTES

_HOST_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def validate_host(host: str) -> str:
    """Validate a hostname for TLS scanning."""
    cleaned = host.strip().lower()
    if not cleaned or len(cleaned) > 253:
        msg = f"Invalid host: {host!r}"
        raise ValueError(msg)
    if cleaned.startswith(".") or cleaned.endswith("."):
        msg = f"Invalid host: {host!r}"
        raise ValueError(msg)
    if not _HOST_PATTERN.match(cleaned):
        msg = f"Invalid host: {host!r}"
        raise ValueError(msg)
    return cleaned


def validate_https_url(url: str) -> str:
    """Validate an HTTPS URL."""
    parsed = urlparse(url.strip())
    if parsed.scheme != "https":
        msg = f"Only https URLs are allowed: {url!r}"
        raise ValueError(msg)
    if not parsed.hostname:
        msg = f"Missing hostname in URL: {url!r}"
        raise ValueError(msg)
    validate_host(parsed.hostname)
    return url.strip()


def safe_read_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    """Read a text file with size limits."""
    resolved = path.resolve()
    if not resolved.is_file():
        msg = f"Not a file: {path}"
        raise ValueError(msg)
    size = resolved.stat().st_size
    if size > max_bytes:
        msg = f"File too large ({size} bytes): {path}"
        raise ValueError(msg)
    return resolved.read_text(encoding="utf-8", errors="replace")


def safe_resolve(base: Path, user_path: str) -> Path:
    """Resolve a path and ensure it stays under base."""
    base_resolved = base.resolve()
    candidate = (base_resolved / user_path).resolve()
    if base_resolved not in candidate.parents and candidate != base_resolved:
        msg = f"Path escapes base directory: {user_path}"
        raise ValueError(msg)
    return candidate
