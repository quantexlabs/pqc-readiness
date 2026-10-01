from pathlib import Path

import pytest

from pqc_readiness.security import safe_resolve, validate_host, validate_https_url


def test_validate_host_ok() -> None:
    assert validate_host("badssl.com") == "badssl.com"


def test_validate_host_bad() -> None:
    with pytest.raises(ValueError):
        validate_host("not a host!")


def test_validate_https_url() -> None:
    assert validate_https_url("https://example.com/path").startswith("https://")


def test_safe_resolve(tmp_path: Path) -> None:
    child = tmp_path / "a"
    child.mkdir()
    assert safe_resolve(tmp_path, "a") == child.resolve()


def test_safe_resolve_escape(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        safe_resolve(tmp_path, "../outside")
