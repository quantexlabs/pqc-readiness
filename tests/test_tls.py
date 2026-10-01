"""TLS scanner tests with mocked socket."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pqc_readiness.scanners.tls import scan_tls_host


def test_scan_tls_host_invalid() -> None:
    result = scan_tls_host("not valid host!!")
    assert result.errors


@patch("pqc_readiness.scanners.tls.socket.create_connection")
def test_scan_tls_with_certificate(mock_conn: MagicMock) -> None:
    root = Path(__file__).resolve().parents[1]
    cert_bytes = (root / "data/evaluation/corpus/proj_rsa_app/certs/rsa2048.pem").read_bytes()
    cert_der = x509.load_pem_x509_certificate(cert_bytes).public_bytes(serialization.Encoding.DER)

    mock_tls = MagicMock()
    mock_tls.getpeercert.side_effect = [
        cert_der,
        {"subject": ((("commonName", "test"),),)},
    ]
    mock_tls.cipher.return_value = None

    mock_sock = MagicMock()
    mock_conn.return_value.__enter__.return_value = mock_sock

    with patch("pqc_readiness.scanners.tls.ssl.SSLContext.wrap_socket") as wrap:
        wrap.return_value.__enter__.return_value = mock_tls
        result = scan_tls_host("example.com", timeout=1.0)

    assert len(result.findings) >= 2


@patch("pqc_readiness.scanners.tls.socket.create_connection")
def test_scan_tls_host_success(mock_conn: MagicMock) -> None:
    mock_tls = MagicMock()
    mock_tls.getpeercert.return_value = None
    mock_tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_tls.version.return_value = "TLSv1.3"

    mock_sock = MagicMock()
    mock_conn.return_value.__enter__.return_value = mock_sock

    with patch("pqc_readiness.scanners.tls.ssl.SSLContext.wrap_socket") as wrap:
        wrap.return_value.__enter__.return_value = mock_tls
        result = scan_tls_host("example.com", timeout=1.0)

    assert result.findings
    assert not result.errors


@patch("pqc_readiness.scanners.tls.socket.create_connection", side_effect=OSError("fail"))
def test_scan_tls_host_os_error(_mock: Any) -> None:
    result = scan_tls_host("example.com", timeout=1.0)
    assert result.errors
