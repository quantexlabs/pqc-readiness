from pathlib import Path

from pqc_readiness.evaluation.ground_truth import load_ground_truth
from pqc_readiness.evaluation.runner import run_evaluation


def test_load_ground_truth() -> None:
    root = Path(__file__).resolve().parents[1]
    corpus = load_ground_truth(root / "data/evaluation/ground_truth.yaml")
    assert len(corpus.items) >= 10
    assert corpus.licence.startswith("Apache")


def test_run_evaluation_fixture() -> None:
    root = Path(__file__).resolve().parents[1]
    result, payload = run_evaluation(
        root / "data/evaluation/corpus",
        root / "data/evaluation/ground_truth.yaml",
        n_bootstrap=100,
    )
    assert result.precision.point == 1.0
    assert result.recall.point == 1.0
    assert "per_project" in payload
