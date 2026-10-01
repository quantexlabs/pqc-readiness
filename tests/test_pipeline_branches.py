"""Pipeline branch coverage."""

from pathlib import Path

from pqc_readiness.models import SensitivityClass
from pqc_readiness.pipeline import PipelineConfig, run_pipeline, write_pipeline_outputs


def test_pipeline_all_inputs(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    corpus = root / "data/evaluation/corpus"
    config = PipelineConfig(
        code_dir=corpus / "proj_mixed_config/src",
        config_dir=corpus / "proj_mixed_config/config",
        known_hosts=corpus / "proj_mixed_config/ssh/known_hosts",
        cert_paths=(corpus / "proj_rsa_app/certs/rsa2048.pem",),
        sensitivity=SensitivityClass.PROTECTED_B,
        lifetime_years=15,
        harvest_exposure=True,
        skip_tls=True,
        output_dir=tmp_path,
    )
    scan = run_pipeline(config)
    paths = write_pipeline_outputs(scan, config)
    assert paths["cbom"].exists()
