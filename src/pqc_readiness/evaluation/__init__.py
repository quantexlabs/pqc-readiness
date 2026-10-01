"""Evaluation package."""

from pqc_readiness.evaluation.ground_truth import (
    GroundTruthCorpus,
    GroundTruthItem,
    load_ground_truth,
)
from pqc_readiness.evaluation.metrics import (
    DetectionMetrics,
    EvaluationResult,
    aggregate_project_metrics,
    compute_metrics,
    verify_scorer_sanity,
)
from pqc_readiness.evaluation.runner import run_evaluation, write_evaluation_results

__all__ = [
    "DetectionMetrics",
    "EvaluationResult",
    "GroundTruthCorpus",
    "GroundTruthItem",
    "aggregate_project_metrics",
    "compute_metrics",
    "load_ground_truth",
    "run_evaluation",
    "verify_scorer_sanity",
    "write_evaluation_results",
]
