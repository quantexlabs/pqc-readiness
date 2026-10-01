from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from pqc_readiness.scanners.codebase import scan_source_file
from pqc_readiness.scanners.config import scan_config_file
from pqc_readiness.scanners.ssh import parse_ssh_known_hosts_line, scan_ssh_public_key_line
from pqc_readiness.scanners.x509 import findings_from_certificate, scan_x509_file


def test_scan_python_rsa(tmp_path: Path) -> None:
    f = tmp_path / "app.py"
    f.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(65537, 2048)\n"
    )
    findings = scan_source_file(f)
    algos = {x.algorithm for x in findings}
    assert "RSA" in algos


def test_scan_config_nginx(tmp_path: Path) -> None:
    f = tmp_path / "nginx.conf"
    f.write_text("ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n")
    findings = scan_config_file(f)
    assert findings


def test_ssh_known_hosts_line() -> None:
    line = "host ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC test"
    finding = parse_ssh_known_hosts_line(line, "known_hosts", 1)
    assert finding is not None
    assert finding.algorithm == "RSA"


def test_ssh_public_key() -> None:
    finding = scan_ssh_public_key_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test")
    assert finding is not None
    assert finding.algorithm == "Ed25519"


def test_x509_findings() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
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
    findings = findings_from_certificate(cert, "test.pem")
    assert any(f.algorithm == "RSA" for f in findings)


def test_scan_config_protocols(tmp_path: Path) -> None:
    f = tmp_path / "site.conf"
    f.write_text("ssl_protocols TLSv1.2 TLSv1.3;\nMinProtocol TLSv1.2\n")
    findings = scan_config_file(f)
    assert len(findings) >= 2


def test_ssh_invalid_lines() -> None:
    assert parse_ssh_known_hosts_line("# comment", "x", 1) is None
    assert parse_ssh_known_hosts_line("", "x", 1) is None


def test_codebase_skips_large(tmp_path: Path) -> None:
    from pqc_readiness.constants import MAX_FILE_BYTES

    f = tmp_path / "big.py"
    f.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    assert scan_source_file(f) == []


def test_x509_ec_and_ed25519(tmp_path: Path) -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec")])
    now = datetime.now(tz=UTC)
    ec_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ec_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(ec_key, hashes.SHA256())
    )
    assert findings_from_certificate(ec_cert, "ec.pem")

    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ed_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(ed_key, None)
    )
    assert findings_from_certificate(ed_cert, "ed.pem")


def test_scan_x509_der(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
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

    pem_path = tmp_path / "c.pem"
    pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    der_path = tmp_path / "c.der"
    der_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    assert scan_x509_file(str(pem_path))
    assert scan_x509_file(str(der_path))
