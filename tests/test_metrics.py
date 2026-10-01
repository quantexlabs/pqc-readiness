from pqc_readiness.evaluation.metrics import (
    aggregate_project_metrics,
    compute_metrics,
    verify_scorer_sanity,
)


def test_scorer_sanity() -> None:
    verify_scorer_sanity()


def test_perfect_metrics() -> None:
    m = compute_metrics({"a", "b"}, {"a", "b"})
    assert m.f1 == 1.0


def test_empty_prediction() -> None:
    m = compute_metrics(set(), {"a"})
    assert m.recall == 0.0


def test_bootstrap_interval() -> None:
    result = aggregate_project_metrics(
        {"p1": {"a", "b"}, "p2": {"c"}},
        {"p1": {"a", "b"}, "p2": {"c", "d"}},
        seed=1,
        n_bootstrap=200,
    )
    assert 0.0 <= result.recall.point <= 1.0
    assert result.recall.lower <= result.recall.point <= result.recall.upper
