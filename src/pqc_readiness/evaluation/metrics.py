"""Evaluation metrics with bootstrap uncertainty."""

from __future__ import annotations

import random
from dataclasses import dataclass
from math import fsum


@dataclass(frozen=True)
class DetectionMetrics:
    """Precision, recall and F1 with support counts."""

    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int
    support: int


@dataclass(frozen=True)
class MetricInterval:
    """Point estimate with bootstrap interval."""

    point: float
    lower: float
    upper: float
    n_bootstrap: int


@dataclass(frozen=True)
class EvaluationResult:
    """Full evaluation output."""

    precision: MetricInterval
    recall: MetricInterval
    f1: MetricInterval
    per_project: dict[str, DetectionMetrics]
    seed: int


def _match(predicted: set[str], expected: set[str]) -> DetectionMetrics:
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return DetectionMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        support=len(expected),
    )


def compute_metrics(predicted_keys: set[str], expected_keys: set[str]) -> DetectionMetrics:
    """Compute detection metrics from unique item keys."""
    return _match(predicted_keys, expected_keys)


def bootstrap_interval(
    values: list[float],
    *,
    n_bootstrap: int = 1000,
    seed: int = 42,
    alpha: float = 0.05,
) -> MetricInterval:
    """Bootstrap percentile interval for a list of per-unit metric values."""
    if not values:
        return MetricInterval(point=0.0, lower=0.0, upper=0.0, n_bootstrap=n_bootstrap)
    rng = random.Random(seed)
    n = len(values)
    means: list[float] = []
    for _ in range(n_bootstrap):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(fsum(sample) / n)
    means.sort()
    lower_idx = int((alpha / 2) * n_bootstrap)
    upper_idx = int((1 - alpha / 2) * n_bootstrap) - 1
    point = fsum(values) / n
    return MetricInterval(
        point=point,
        lower=means[lower_idx],
        upper=means[upper_idx],
        n_bootstrap=n_bootstrap,
    )


def aggregate_project_metrics(
    per_project_pred: dict[str, set[str]],
    per_project_expected: dict[str, set[str]],
    *,
    seed: int = 42,
    n_bootstrap: int = 1000,
) -> EvaluationResult:
    """Resample whole projects and compute macro-averaged intervals."""
    projects = sorted(set(per_project_pred) | set(per_project_expected))
    per_project: dict[str, DetectionMetrics] = {}
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []

    for project in projects:
        pred = per_project_pred.get(project, set())
        expected = per_project_expected.get(project, set())
        m = compute_metrics(pred, expected)
        per_project[project] = m
        precisions.append(m.precision)
        recalls.append(m.recall)
        f1s.append(m.f1)

    return EvaluationResult(
        precision=bootstrap_interval(precisions, n_bootstrap=n_bootstrap, seed=seed),
        recall=bootstrap_interval(recalls, n_bootstrap=n_bootstrap, seed=seed + 1),
        f1=bootstrap_interval(f1s, n_bootstrap=n_bootstrap, seed=seed + 2),
        per_project=per_project,
        seed=seed,
    )


def verify_scorer_sanity() -> None:
    """Verify perfect system scores 1.0 and empty system scores 0.0."""
    perfect = compute_metrics({"a", "b"}, {"a", "b"})
    if perfect.precision != 1.0 or perfect.recall != 1.0 or perfect.f1 != 1.0:
        msg = "Perfect prediction must score 1.0"
        raise RuntimeError(msg)
    empty = compute_metrics(set(), {"a", "b"})
    if empty.precision != 0.0 or empty.recall != 0.0 or empty.f1 != 0.0:
        msg = "Empty prediction must score 0.0"
        raise RuntimeError(msg)
