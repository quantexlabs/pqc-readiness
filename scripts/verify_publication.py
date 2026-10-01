#!/usr/bin/env python3
"""Audit an explicit publication ref, including every reachable tree and commit.

Quoted logs and test fixtures have no exemption. The requested human commit identity
is authorized metadata; copyright and licence notices remain in shipped content.
This bounded pattern scan is neither a proof of secret absence nor an ownership audit.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import PurePosixPath

AUTHORIZED_NAME = "Amirhossein (Amir) Daneshpajouh"
AUTHORIZED_EMAIL = "52765136+Daneshpajouh@users.noreply.github.com"
FORBIDDEN_PARTS = {".review", ".venv", "state", "__pycache__"}
TEXT_RULES = {
    "home_coordinate": re.compile(r"/(?:" + "Users" + r"|home)/"),
    "em_dash": re.compile(chr(8212)),
    "private_review_reference": re.compile(re.escape("." + "review/")),
    "model_family": re.compile(
        r"\b(?:" + "GP" + r"T(?:-\d+)?|Res" + r"Net(?:-\d+)?|YO" + r"LO(?:v\d+)?)\b", re.I
    ),
    "attribution_trailer": re.compile("co-" + "authored-by:", re.I),
}
SECRET_RULES = {
    "private_key_header": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "github_fine_grained": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "provider_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    "credential_assignment": re.compile(
        r"(?i)\b(?:password|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*"
        r"[\"']([A-Za-z0-9_+/-]{16,})[\"']"
    ),
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def violations(text: str, rules: dict[str, re.Pattern[str]]) -> list[dict[str, object]]:
    """Return coordinates/rule names only, never matched sensitive content."""
    return [
        {"line": text.count("\n", 0, match.start()) + 1, "rule": name}
        for name, pattern in rules.items()
        for match in pattern.finditer(text)
    ]


def audit(ref: str) -> dict[str, object]:
    commit = git("rev-parse", "--verify", ref + "^{commit}").decode().strip()
    commits = git("rev-list", commit).decode().splitlines()
    forbidden: list[dict[str, str]] = []
    text_violations: list[dict[str, object]] = []
    secret_findings: list[dict[str, object]] = []
    metadata_violations: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    text_blobs = 0
    binary_blobs = 0
    head_files = 0
    for revision in commits:
        metadata = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", revision)
        author, email, committer, committer_email, _message = metadata.decode().split("\0", 4)
        if (author, email, committer, committer_email) != (
            AUTHORIZED_NAME,
            AUTHORIZED_EMAIL,
            AUTHORIZED_NAME,
            AUTHORIZED_EMAIL,
        ):
            metadata_violations.append({"commit": revision, "rule": "unauthorized_identity"})
        metadata_text = metadata.decode()
        metadata_violations.extend(
            {"commit": revision, **item} for item in violations(metadata_text, TEXT_RULES)
        )
        secret_findings.extend(
            {"commit": revision, "file": "commit metadata/message", **item}
            for item in violations(metadata_text, SECRET_RULES)
        )
        entries = git("ls-tree", "-rz", revision).split(b"\0")
        if revision == commit:
            head_files = len([entry for entry in entries if entry])
        for entry in filter(None, entries):
            header, raw_name = entry.split(b"\t", 1)
            mode, kind, raw_oid = header.decode().split()
            name = raw_name.decode()
            oid = raw_oid
            if (name, oid) in seen:
                continue
            seen.add((name, oid))
            coordinate = {"commit": revision, "file": name}
            if any(part in FORBIDDEN_PARTS for part in PurePosixPath(name).parts):
                forbidden.append({**coordinate, "rule": "private_file"})
            if kind != "blob" or mode == "120000":
                forbidden.append({**coordinate, "rule": "non_regular_file"})
                continue
            text_violations.extend({**coordinate, **item} for item in violations(name, TEXT_RULES))
            payload = git("cat-file", "blob", oid)
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                binary_blobs += 1
                # Known binary formats need a separate manual release review.
                forbidden.append({**coordinate, "rule": "unreviewed_binary"})
                continue
            text_blobs += 1
            text_violations.extend({**coordinate, **item} for item in violations(text, TEXT_RULES))
            secret_findings.extend(
                {**coordinate, **item} for item in violations(text, SECRET_RULES)
            )
    return {
        "ref": ref,
        "commit": commit,
        "tree": git("rev-parse", commit + "^{tree}").decode().strip(),
        "reachable_commits": len(commits),
        "tracked_file_count": head_files,
        "text_blobs_screened": text_blobs,
        "binary_blobs": binary_blobs,
        "forbidden_files": forbidden,
        "text_violations": text_violations,
        "metadata_violations": metadata_violations,
        "secret_findings": secret_findings,
        "secret_rules": list(SECRET_RULES),
        "identity_policy": "requested human author/committer; no anonymous-metadata claim",
        "scope": (
            "all reachable commit trees, names, author/committer metadata and messages for this ref"
        ),
        "limitations": (
            "bounded credential patterns; no proof of absence or ownership; no remote-ref audit"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="HEAD", help="Only this ref and its ancestors are audited")
    args = parser.parse_args()
    receipt = audit(args.ref)
    print(json.dumps(receipt, indent=2))
    return int(
        any(
            receipt[name]
            for name in (
                "forbidden_files",
                "text_violations",
                "metadata_violations",
                "secret_findings",
            )
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
