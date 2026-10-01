"""Targeted coverage for pipeline, paths, and classification branches."""

from pathlib import Path

from pqc_readiness.classification.priority import (
    build_migration_plan,
    classify_quantum_risk,
    score_migration_priority,
)
from pqc_readiness.evaluation.keys import evaluation_key
from pqc_readiness.models import (
    CryptoFinding,
    EvidenceSource,
    MigrationPriority,
    QuantumRisk,
    SensitivityClass,
)
from pqc_readiness.paths import display_path, find_repo_root, format_location
from pqc_readiness.pipeline import PipelineConfig, run_pipeline
from pqc_readiness.scanners.codebase import scan_code_directory, scan_source_file
from pqc_readiness.scanners.config import scan_config_directory, scan_config_file


def test_paths_outside_repo_use_basename(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n")
    assert display_path(outside, repo_root=Path(__file__).resolve().parents[1]) == "outside.py"


def test_find_repo_root_from_file() -> None:
    root = find_repo_root(Path(__file__).resolve())
    assert (root / "pyproject.toml").is_file()


def test_format_location_with_suffix() -> None:
    loc = format_location(Path("data/app.pem"), suffix="signature")
    assert loc.endswith("/signature")


def test_ssh_evaluation_key_adds_line() -> None:
    finding = CryptoFinding(
        finding_id="x",
        source=EvidenceSource.SSH,
        algorithm="RSA",
        key_size=None,
        location="data/known_hosts",
        evidence="e",
        quantum_risk=QuantumRisk.VULNERABLE,
        migration_priority=MigrationPriority.HIGH,
        metadata={"line": 2},
    )
    key = evaluation_key("proj", finding)
    assert key.startswith("proj:")


def test_classification_branches() -> None:
    assert classify_quantum_risk("AES", 256) == QuantumRisk.SAFE
    assert classify_quantum_risk("SHA3-256") == QuantumRisk.SAFE
    assert classify_quantum_risk("ChaCha20") == QuantumRisk.SAFE
    assert score_migration_priority(
        QuantumRisk.VULNERABLE,
        SensitivityClass.UNCLASSIFIED,
        lifetime_years=5,
        harvest_exposure=False,
        is_signature_use=False,
    ) in (MigrationPriority.MEDIUM, MigrationPriority.HIGH)


def test_plan_reduced_and_unknown_recommendations() -> None:
    reduced = CryptoFinding(
        finding_id="r1",
        source=EvidenceSource.CODE,
        algorithm="AES-128",
        key_size=128,
        location="a.py:1",
        evidence="aes",
        quantum_risk=QuantumRisk.REDUCED,
        migration_priority=MigrationPriority.MEDIUM,
    )
    unknown = CryptoFinding(
        finding_id="u1",
        source=EvidenceSource.CODE,
        algorithm="CUSTOM",
        key_size=None,
        location="a.py:2",
        evidence="x",
        quantum_risk=QuantumRisk.UNKNOWN,
        migration_priority=MigrationPriority.MEDIUM,
    )
    plan = build_migration_plan([reduced, unknown])
    texts = " ".join(a.action for a in plan.actions)
    assert "AES-256" in texts or "Monitor" in texts


def test_pipeline_missing_optional_dirs_warns() -> None:
    scan = run_pipeline(
        PipelineConfig(
            code_dir=Path("missing-code-dir"),
            config_dir=Path("missing-config-dir"),
            skip_tls=True,
        )
    )
    assert scan.warnings


def test_pipeline_missing_corpus_records_error() -> None:
    scan = run_pipeline(PipelineConfig(corpus_dir=Path("missing-corpus"), skip_tls=True))
    assert scan.errors


def test_code_scanner_dsa_and_skip_helpers(tmp_path: Path) -> None:
    f = tmp_path / "app.py"
    f.write_text("DSA.generate(1024)\n")
    findings = scan_source_file(f)
    assert any(x.algorithm == "DSA" for x in findings)
    helper = tmp_path / "_helper.py"
    helper.write_text("RSA.generate(2048)\n")
    assert scan_source_file(helper) == []


def test_pipeline_require_inputs_errors() -> None:
    scan = run_pipeline(
        PipelineConfig(
            code_dir=Path("missing-required-code"),
            skip_tls=True,
            require_inputs=True,
        )
    )
    assert scan.errors


def test_config_legacy_tls_and_ml_kem(tmp_path: Path) -> None:
    f = tmp_path / "nginx.conf"
    f.write_text("ssl_protocols TLSv1.0;\nssl_ciphers HIGH:!aNULL:kyber768;\n")
    algos = {x.algorithm for x in scan_config_file(f)}
    assert "TLS-LEGACY" in algos or "ML-KEM" in algos


def test_pipeline_missing_cert_and_known_hosts_require_inputs(tmp_path: Path) -> None:
    scan = run_pipeline(
        PipelineConfig(
            cert_paths=(tmp_path / "missing.pem",),
            known_hosts=tmp_path / "missing_hosts",
            skip_tls=True,
            require_inputs=True,
        )
    )
    assert scan.errors


def test_x509_dsa_branch(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa
    from cryptography.x509.oid import NameOID

    from pqc_readiness.scanners.x509 import findings_from_certificate

    key = dsa.generate_private_key(key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dsa")])
    now = datetime.now(tz=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    findings = findings_from_certificate(cert, "dsa.pem")
    assert any(f.algorithm == "DSA" for f in findings)


def test_code_directory_file_cap(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    for i in range(3):
        (src / f"file{i}.py").write_text("ML-KEM\n")
    findings = scan_code_directory(src, max_files=1)
    assert findings


def test_config_ed448_and_scan_directory(tmp_path: Path) -> None:
    f = tmp_path / "sshd_config"
    f.write_text("HostKeyAlgorithms ssh-ed448\n")
    finding = scan_config_file(f)[0]
    assert finding.algorithm == "Ed448"
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "site.conf").write_text("ssl_protocols TLSv1.2;\n")
    assert scan_config_directory(nested)
