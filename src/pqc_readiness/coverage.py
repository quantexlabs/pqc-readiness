"""Scan coverage tracking for partial and truncated runs."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanCoverage:
    """Counts for requested, scanned, skipped, and truncated inputs."""

    requested_paths: list[str] = field(default_factory=lambda: [])
    scanned_paths: list[str] = field(default_factory=lambda: [])
    skipped_paths: list[str] = field(default_factory=lambda: [])
    failed_paths: list[str] = field(default_factory=lambda: [])
    local_targets_scanned: int = 0
    projects_scanned: int = 0
    files_scanned: int = 0
    files_skipped_size: int = 0
    files_truncated_cap: int = 0
    actions_emitted: int = 0
    findings_emitted: int = 0
    findings_report_limit: int = 500
    findings_truncated: bool = False

    def add_requested(self, path: str) -> None:
        self.requested_paths.append(path)

    def add_scanned(self, path: str) -> None:
        self.scanned_paths.append(path)

    def add_skipped(self, path: str, reason: str) -> None:
        self.skipped_paths.append(f"{path} ({reason})")

    def add_failed(self, path: str, reason: str) -> None:
        self.failed_paths.append(f"{path} ({reason})")

    def to_dict(self) -> dict[str, object]:
        return {
            "requested_count": len(self.requested_paths),
            "requested_targets": len(self.requested_paths),
            "local_targets_scanned": self.local_targets_scanned,
            "projects_scanned": self.projects_scanned,
            "status": (
                "partial"
                if self.failed_paths
                or self.skipped_paths
                or self.files_skipped_size
                or self.files_truncated_cap
                else "complete"
            ),
            "scanned_count": len(self.scanned_paths),
            "skipped_count": len(self.skipped_paths),
            "failed_count": len(self.failed_paths),
            "files_scanned": self.files_scanned,
            "files_skipped_size": self.files_skipped_size,
            "files_truncated_cap": self.files_truncated_cap,
            "findings_emitted": self.findings_emitted,
            "findings_displayed": min(self.findings_emitted, self.findings_report_limit),
            "actions_emitted": self.actions_emitted,
            "actions_displayed": min(self.actions_emitted, 200),
            "findings_truncated": self.findings_truncated,
            "skipped_paths": self.skipped_paths,
            "failed_paths": self.failed_paths,
        }
