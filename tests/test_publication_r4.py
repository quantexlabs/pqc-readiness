"""Round four behavioral regressions and bounded publication contracts."""

from __future__ import annotations

import json
import math
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

import pytest

from pqc_readiness.classification.priority import build_migration_plan
from pqc_readiness.evaluation.metrics import bootstrap_interval
from pqc_readiness.models import MigrationPriority, QuantumRisk, SensitivityClass
from pqc_readiness.pipeline import PipelineConfig, run_pipeline
from pqc_readiness.report.html import render_report
from pqc_readiness.scanners.config import scan_config_file

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = "Amirhossein (Amir) Daneshpajouh"
EMAIL = "52765136+Daneshpajouh@users.noreply.github.com"


def test_finding_1_work_sample_ceiling() -> None:
    text = (ROOT / "README.md").read_text()
    assert "Limited engineering work sample" in text
    assert "No independently reviewed real-world case study" in text
    assert "Independent validation remains blocked" in text


def test_finding_2_stable_aggregation_and_constraints() -> None:
    values = [0.1, 0.2, 0.3]
    assert bootstrap_interval(values).point == math.fsum(values) / len(values)
    constraints = (ROOT / "requirements-dev.txt").read_text()
    assert "cryptography==" in constraints and "pytest==" in constraints
    assert "-c requirements-dev.txt" in (ROOT / ".github/workflows/ci.yml").read_text()


@pytest.mark.parametrize(
    "directive",
    [
        "ssl_ciphers ML-KEM-768;",
        "ssl_ciphers Kyber768:CHACHA20;",
        "ssl_ciphers unsupported-ML-KEM-token;",
        "Ciphers chacha20-poly1305@openssh.com",
        "KEXAlgorithms ML-KEM-768",
        "ssl_ciphers ECDHE-RSA-AES128:ML-KEM-768;",
    ],
)
def test_finding_3_config_requires_verification(tmp_path: Path, directive: str) -> None:
    path = tmp_path / "nginx.conf"
    path.write_text(directive + "\n")
    findings = scan_config_file(path)
    assert findings
    assert all(f.quantum_risk != QuantumRisk.SAFE for f in findings)
    assert all(f.migration_priority != MigrationPriority.MONITOR for f in findings)
    plan = build_migration_plan(findings)
    assert len(plan.actions) == len(findings)
    if "RSA" not in directive:
        assert all(f.quantum_risk == QuantumRisk.UNKNOWN for f in findings)
        assert all("Verify" in action.action for action in plan.actions)
    assert all(f.metadata["observation"] == "configuration_directive" for f in findings)


@pytest.mark.parametrize("kind", ["code", "config"])
@pytest.mark.parametrize("failure", [PermissionError, ValueError])
def test_finding_4_retain_successes_around_failure(
    tmp_path: Path, kind: str, failure: type[Exception]
) -> None:
    extension = ".py" if kind == "code" else ".conf"
    content = "hashlib.sha256(b'x')\n" if kind == "code" else "ssl_ciphers ECDHE-RSA-AES128;\n"
    for name in ("a", "b", "c"):
        (tmp_path / (name + extension)).write_text(content)
    from pqc_readiness.security import safe_read_text

    def read(path: Path) -> str:
        if path.stem == "b":
            raise failure(str(path))
        return safe_read_text(path)

    module = "codebase" if kind == "code" else "config"
    with patch(f"pqc_readiness.scanners.{module}.safe_read_text", side_effect=read):
        config = (
            PipelineConfig(skip_tls=True, code_dir=tmp_path)
            if kind == "code"
            else PipelineConfig(skip_tls=True, config_dir=tmp_path)
        )
        scan = run_pipeline(config)
    assert len(scan.findings) == 2
    assert scan.coverage.files_scanned == 2
    assert len(scan.coverage.failed_paths) == 1
    assert "b" + extension in scan.coverage.failed_paths[0]
    assert str(tmp_path) not in json.dumps(asdict(scan))
    assert failure.__name__ in scan.errors[0]
    assert scan.coverage.to_dict()["status"] == "partial"


def test_finding_5_public_text_hygiene() -> None:
    targets = [
        ROOT / "tests/test_publication_fixes.py",
        ROOT / "tests/test_publication_r3.py",
        *sorted((ROOT / "docs/evidence/r3").glob("*.txt")),
    ]
    home = "/" + "Users" + "/"
    private = "." + "review/"
    for path in targets:
        content = path.read_text()
        assert home not in content, path.name
        assert chr(8212) not in content, path.name
        assert private not in content, path.name


def test_finding_6_pinned_schema_lineage() -> None:
    provenance = json.loads((ROOT / "data/schemas/provenance.json").read_text())
    assert provenance["upstream_revision"] == "55343ba19dee1785acf1ce9191540d5fd7b590db"
    assert provenance["upstream_sha256"] == (
        "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93"
    )
    assert provenance["consumer_ingestion"] == "unverified"
    assert (ROOT / "scripts/validate_schema.py").is_file()


def test_finding_7_units_and_replay_ceiling() -> None:
    assert "10 MiB" in (ROOT / "README.md").read_text()
    assert "eagerly enumerates" in (ROOT / "README.md").read_text()
    report = (ROOT / "docs/milestones/PUBLICATION_FIX_REPORT_R3_2026-10-01.md").read_text()
    assert "initial 16" not in report
    results = (ROOT / "RESULTS.md").read_text()
    assert "Macro metrics" in results and "pooled counts" in results
    assert "not generalization" in results


def fixture_report() -> str:
    scan = run_pipeline(PipelineConfig(corpus_dir=ROOT / "data/evaluation/corpus", skip_tls=True))
    return render_report(scan, build_migration_plan(scan.findings), {})


def test_finding_8_bounded_header_and_prior_art() -> None:
    assert (
        "Uses selected CCCS milestone dates; priority scoring is unofficial and unvalidated."
        in fixture_report()
    )
    text = (ROOT / "docs/PRIOR_ART.md").read_text()
    assert "cbomkit/cbomkit/blob/" in text
    assert "cbomkit/sonar-cryptography/blob/" in text
    assert "No competitor was executed" in text


def audit_repo(
    tmp_path: Path, content: str, *, message: str = "Publication check"
) -> subprocess.CompletedProcess[str]:
    shutil.copy(ROOT / "scripts/verify_publication.py", tmp_path / "audit.py")
    (tmp_path / "quoted.txt").write_text(content)
    (tmp_path / "data/schemas").mkdir(parents=True)
    (tmp_path / "data/schemas/bom-1.6.schema.json").write_text("{}")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    commands = [
        ["add", "."],
        [
            "-c",
            "user.name=" + IDENTITY,
            "-c",
            "user.email=" + EMAIL,
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            message,
        ],
    ]
    for command in commands:
        subprocess.run(["git", *command], cwd=tmp_path, check=True)
    return subprocess.run(
        [sys.executable, "audit.py", "--ref", "HEAD"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )


def test_finding_9_secret_audit_contract(tmp_path: Path) -> None:
    # Construct a fake credential at runtime; neither the token nor its family is shipped.
    token = "gh" + "p_" + "A" * 36
    proc = audit_repo(tmp_path, token)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    receipt = json.loads(proc.stdout)
    assert receipt["secret_findings"]
    assert token not in proc.stdout
    assert "certificate subjects and SSH host markers" in (ROOT / "README.md").read_text()


@pytest.mark.parametrize(
    "content",
    ["/" + "Users" + "/sample/file", chr(8212), "." + "review/private.md", "GP" + "T-" + "9"],
)
def test_auditor_checks_quoted_text(tmp_path: Path, content: str) -> None:
    proc = audit_repo(tmp_path, content)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["text_violations"]


def test_auditor_checks_commit_metadata(tmp_path: Path) -> None:
    proc = audit_repo(tmp_path, "clean", message="bad " + chr(8212) + " metadata")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["metadata_violations"]


def test_auditor_checks_deleted_history(tmp_path: Path) -> None:
    token = "gh" + "p_" + "B" * 36
    audit_repo(tmp_path, token)
    (tmp_path / "quoted.txt").write_text("clean")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=" + IDENTITY,
            "-c",
            "user.email=" + EMAIL,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "Remove synthetic token",
        ],
        cwd=tmp_path,
        check=True,
    )
    # Historical evidence is screened even after it disappears from the tip tree.
    proc = subprocess.run(
        [sys.executable, "audit.py", "--ref", "HEAD"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    receipt = json.loads(proc.stdout)
    assert receipt["reachable_commits"] == 2
    assert receipt["secret_findings"]
    assert token not in proc.stdout


def test_finding_10_complete_licenses() -> None:
    for name in ("LICENSE", "data/schemas/LICENSE"):
        text = (ROOT / name).read_text()
        assert "APPENDIX: How to apply the Apache License to your work." in text
        assert "limitations under the License." in text
    assert (ROOT / "LICENSING.md").is_file()


def test_finding_11_traceable_owner_workflow() -> None:
    report = fixture_report()
    assert "Cryptographic observations" in report
    assert "Observation to verification" in report
    assert "Asset-owner workflow" in report
    assert "fixture-based engineering work sample" in (ROOT / "README.md").read_text()
    assert "Release evidence" in (ROOT / "README.md").read_text()


def test_workflow_uses_actual_policy_inputs() -> None:
    scan = run_pipeline(PipelineConfig(corpus_dir=ROOT / "data/evaluation/corpus", skip_tls=True))
    plan = build_migration_plan(
        scan.findings,
        sensitivity=SensitivityClass.PUBLIC,
        default_lifetime_years=2,
        harvest_exposure=False,
    )
    report = render_report(scan, plan, {})
    workflow = report.split('<section id="workflow"', 1)[1].split("</section>", 1)[0]
    assert "sensitivity public" in workflow
    assert "lifetime 2y" in workflow
    assert "harvest exposure False" in workflow
    assert "lifetime 10 years" not in workflow
