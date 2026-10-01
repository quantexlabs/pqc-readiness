"""Ground truth and security edge tests."""


import pytest

from pqc_readiness.evaluation.ground_truth import GroundTruthCorpus, GroundTruthItem
from pqc_readiness.security import validate_host, validate_https_url


def test_ground_truth_reject_excluded() -> None:
    corpus = GroundTruthCorpus(
        items=[
            GroundTruthItem(
                item_key="p1:k1",
                project_id="p1",
                algorithm="RSA",
                source_type="code",
                evidence_line="x",
                human_verdict="reject",
            ),
            GroundTruthItem(
                item_key="p1:k2",
                project_id="p1",
                algorithm="EC",
                source_type="code",
                evidence_line="y",
            ),
        ],
        licence="test",
        provenance="test",
    )
    keys = corpus.expected_keys_by_project()
    assert "p1:k1" not in keys["p1"]
    assert "p1:k2" in keys["p1"]


def test_validate_https_url_errors() -> None:
    with pytest.raises(ValueError):
        validate_https_url("http://example.com")
    with pytest.raises(ValueError):
        validate_https_url("https://")


def test_validate_host_edge() -> None:
    with pytest.raises(ValueError):
        validate_host(".bad.com")
