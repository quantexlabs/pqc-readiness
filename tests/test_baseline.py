"""Baseline scanner coverage."""

from pathlib import Path

from pqc_readiness.evaluation.baseline import baseline_scan_project
from pqc_readiness.evaluation.ground_truth import load_ground_truth
from pqc_readiness.evaluation.metrics import aggregate_project_metrics
from pqc_readiness.evaluation.runner import predicted_keys_by_project, run_evaluation


def test_full_evaluation_perfect_recall() -> None:
    root = Path(__file__).resolve().parents[1]
    result, _ = run_evaluation(
        root / "data/evaluation/corpus",
        root / "data/evaluation/ground_truth.yaml",
        n_bootstrap=50,
    )
    assert result.recall.point == 1.0


def test_baseline_scan_runs() -> None:
    root = Path(__file__).resolve().parents[1]
    corpus_dir = root / "data/evaluation/corpus"
    gt = load_ground_truth(root / "data/evaluation/ground_truth.yaml")
    scans = [
        baseline_scan_project(corpus_dir, pid) for pid in sorted({i.project_id for i in gt.items})
    ]
    assert all(s.findings for s in scans)
    predicted = predicted_keys_by_project(scans)
    expected = gt.expected_keys_by_project()
    result = aggregate_project_metrics(predicted, expected, n_bootstrap=50)
    assert result.f1.point <= 1.0
