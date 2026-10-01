"""Ground truth loading from independent adjudication files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pqc_readiness.security import safe_resolve


@dataclass(frozen=True)
class GroundTruthItem:
    """One independently labelled expected detection."""

    item_key: str
    project_id: str
    algorithm: str
    source_type: str
    evidence_line: str
    human_verdict: str | None = None


@dataclass
class GroundTruthCorpus:
    """Full evaluation ground truth."""

    items: list[GroundTruthItem]
    licence: str
    provenance: str

    def expected_keys_by_project(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for item in self.items:
            if item.human_verdict == "reject":
                continue
            out.setdefault(item.project_id, set()).add(item.item_key)
        return out

    def all_expected_keys(self) -> set[str]:
        keys: set[str] = set()
        for project_keys in self.expected_keys_by_project().values():
            keys |= project_keys
        return keys


def load_ground_truth(path: Path, base_dir: Path | None = None) -> GroundTruthCorpus:
    """Load ground truth YAML with safe path resolution."""
    resolved = path.resolve()
    if base_dir is not None:
        resolved = safe_resolve(base_dir, str(path))
    raw: dict[str, Any] = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    items: list[GroundTruthItem] = []
    for entry in raw.get("items", []):
        items.append(
            GroundTruthItem(
                item_key=str(entry["item_key"]),
                project_id=str(entry["project_id"]),
                algorithm=str(entry["algorithm"]),
                source_type=str(entry["source_type"]),
                evidence_line=str(entry["evidence_line"]),
                human_verdict=entry.get("human_verdict"),
            )
        )
    return GroundTruthCorpus(
        items=items,
        licence=str(raw.get("licence", "unknown")),
        provenance=str(raw.get("provenance", "")),
    )
