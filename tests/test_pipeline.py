import os
from pathlib import Path

import pytest

from pqc_readiness.pipeline import PipelineConfig, run_pipeline, write_pipeline_outputs


def test_pipeline_local_corpus(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    config = PipelineConfig(
        code_dir=root / "data/evaluation/corpus/proj_rsa_app/src",
        skip_tls=True,
        output_dir=tmp_path / "out",
    )
    scan = run_pipeline(config)
    assert scan.findings
    paths = write_pipeline_outputs(scan, config)
    assert paths["report"].is_file()
    assert paths["cbom"].is_file()


@pytest.mark.network
@pytest.mark.skipif(
    os.environ.get("PQC_LIVE_TLS") != "1",
    reason="live TLS success is unverified; opt in with PQC_LIVE_TLS=1",
)
def test_tls_badssl() -> None:
    from pqc_readiness.scanners.tls import scan_tls_host

    result = scan_tls_host("badssl.com", timeout=15.0)
    assert result.findings
    assert not result.errors
