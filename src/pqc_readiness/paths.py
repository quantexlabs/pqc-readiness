"""Repository-relative paths and stable identifiers."""

from __future__ import annotations

import hashlib
from pathlib import Path


def find_repo_root(start: Path | None = None) -> Path:
    """Walk upward from start (or cwd) to locate the repository root."""
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return current if current.is_dir() else current.parent


def display_path(path: Path | str, repo_root: Path | None = None) -> str:
    """Return a repository-relative path for public output."""
    resolved = Path(path).resolve()
    root = (repo_root or find_repo_root(resolved)).resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return resolved.name


def format_location(
    path: Path | str,
    line: int | None = None,
    suffix: str = "",
    *,
    scan_root: Path | None = None,
    namespace: str = "",
) -> str:
    """Build a stable, repository-relative location string."""
    base = display_path(path, scan_root)
    if namespace:
        base = f"{namespace}/{base}"
    if suffix:
        base = f"{base}/{suffix}"
    if line is not None:
        return f"{base}:{line}"
    return base


def stable_digest(*parts: str, length: int = 16) -> str:
    """Hash parts into a short stable identifier."""
    return hashlib.sha256(":".join(parts).encode()).hexdigest()[:length]


def make_finding_id(prefix: str, *parts: str) -> str:
    """Create a root-independent finding identifier."""
    return f"{prefix}-{stable_digest(*parts)}"
