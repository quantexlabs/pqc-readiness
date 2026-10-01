"""Integrity manifests must reject edits even outside generated artifact content."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_integrity_manifest_rejects_annotation_edit(tmp_path: Path) -> None:
    for name in ("src", "data", "scripts", "results"):
        shutil.copytree(ROOT / name, tmp_path / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    script = tmp_path / "scripts/regenerate_results.py"
    initial = subprocess.run(
        [sys.executable, str(script), "--check"], cwd=tmp_path, capture_output=True, text=True
    )
    assert initial.returncode == 0, initial.stdout + initial.stderr
    provenance = tmp_path / "data/schemas/PROVENANCE.md"
    provenance.write_text(provenance.read_text() + "\nSynthetic integrity mutation.\n")
    proc = subprocess.run(
        [sys.executable, str(script), "--check"], cwd=tmp_path, capture_output=True, text=True
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "Stale checksums" in proc.stdout
