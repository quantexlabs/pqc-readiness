"""CLI tests."""

from pathlib import Path

from pqc_readiness.cli import main


def test_cli_evaluate(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "eval.json"
    code = main(
        [
            "evaluate",
            "--corpus-dir",
            str(root / "data/evaluation/corpus"),
            "--ground-truth",
            str(root / "data/evaluation/ground_truth.yaml"),
            "--output",
            str(out),
            "--n-bootstrap",
            "50",
        ]
    )
    assert code == 0
    assert out.is_file()


def test_cli_scan_skip_tls(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    code = main(
        [
            "scan",
            "--skip-tls",
            "--code-dir",
            str(root / "data/evaluation/corpus/proj_rsa_app/src"),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert (tmp_path / "report.html").is_file()


def test_cli_pipeline(tmp_path: Path) -> None:
    code = main(
        [
            "pipeline",
            "--skip-tls",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert (tmp_path / "evaluation.json").is_file()
