#!/usr/bin/env python3
"""Regenerate evaluation results and figures from code."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pqc_readiness.evaluation.baseline import baseline_scan_project  # noqa: E402
from pqc_readiness.evaluation.ground_truth import load_ground_truth  # noqa: E402
from pqc_readiness.evaluation.metrics import aggregate_project_metrics  # noqa: E402
from pqc_readiness.evaluation.runner import (  # noqa: E402
    predicted_keys_by_project,
    run_evaluation,
    write_evaluation_results,
)


def _payload_from_result(result, corpus, seed: int, n_bootstrap: int, label: str) -> dict:
    from dataclasses import asdict

    return {
        "system": label,
        "seed": seed,
        "n_bootstrap": n_bootstrap,
        "licence": corpus.licence,
        "metric_scope": "algorithm_presence_by_location",
        "precision": asdict(result.precision),
        "recall": asdict(result.recall),
        "f1": asdict(result.f1),
        "per_project": {
            pid: {
                "precision": m.precision,
                "recall": m.recall,
                "f1": m.f1,
                "tp": m.true_positives,
                "fp": m.false_positives,
                "fn": m.false_negatives,
                "support": m.support,
            }
            for pid, m in result.per_project.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail on stale normalized artifacts")
    args = parser.parse_args()
    corpus_dir = ROOT / "data" / "evaluation" / "corpus"
    gt_path = ROOT / "data" / "evaluation" / "ground_truth.yaml"
    out_dir = ROOT / "results" / "evaluation"
    out_dir.mkdir(parents=True, exist_ok=True)

    seed = 42
    n_bootstrap = 1000

    _, primary = run_evaluation(corpus_dir, gt_path, seed=seed, n_bootstrap=n_bootstrap)
    primary["system"] = "pqc-readiness"

    corpus = load_ground_truth(gt_path)
    project_ids = sorted({item.project_id for item in corpus.items})
    baseline_scans = [baseline_scan_project(corpus_dir, pid) for pid in project_ids]
    predicted = predicted_keys_by_project(baseline_scans)
    expected = corpus.expected_keys_by_project()
    baseline_result = aggregate_project_metrics(
        predicted, expected, seed=seed, n_bootstrap=n_bootstrap
    )
    baseline_payload = _payload_from_result(
        baseline_result, corpus, seed, n_bootstrap, "regex-baseline"
    )
    baseline_payload["baseline_note"] = (
        "Naive regex baseline implemented in-tree. "
        "IBM CBOMkit-hyperion requires SonarQube and was not attempted in this environment."
    )

    combined = {"primary": primary, "baseline": baseline_payload}
    outputs = {out_dir / "results.json": json.dumps(combined, indent=2, sort_keys=True) + "\n"}
    _, primary_only = run_evaluation(corpus_dir, gt_path, seed=seed, n_bootstrap=n_bootstrap)
    outputs[out_dir / "primary.json"] = json.dumps(primary_only, indent=2, sort_keys=True) + "\n"

    svg = _render_svg(primary, baseline_payload)
    outputs[out_dir / "metrics.svg"] = svg
    from pqc_readiness.pipeline import PipelineConfig, run_pipeline, write_pipeline_outputs

    with tempfile.TemporaryDirectory() as temporary:
        config = PipelineConfig(corpus_dir=corpus_dir, skip_tls=True, output_dir=Path(temporary))
        paths = write_pipeline_outputs(run_pipeline(config), config)
        paths["evaluation"] = Path(temporary) / "evaluation.json"
        write_evaluation_results(primary_only, paths["evaluation"])
        for path in paths.values():
            outputs[ROOT / "results/latest" / path.name] = path.read_text()
    stale = []
    for path, content in outputs.items():
        if args.check:
            if not path.exists() or normalize_artifact(path.read_text()) != normalize_artifact(
                content
            ):
                stale.append(path.relative_to(ROOT).as_posix())
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    if stale:
        print("Stale artifacts: " + ", ".join(stale))
        return 1
    # Check raw committed bytes separately from normalized regeneration equality.
    # UUID/timestamp variation cannot excuse a stale or incorrect integrity manifest.
    checksum_path = ROOT / "data/CHECKSUMS.json"
    checksums = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for directory in (ROOT / "data", ROOT / "results")
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path != checksum_path and "__pycache__" not in path.parts
    }
    content = json.dumps(checksums, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not checksum_path.exists() or checksum_path.read_text() != content:
            print("Stale checksums: data/CHECKSUMS.json")
            return 1
    else:
        checksum_path.write_text(content)
    print(
        "Artifact/checksum check passed"
        if args.check
        else "Regenerated 8 fixture artifacts and checksums"
    )
    return 0


def normalize_artifact(content: str) -> str:
    """Ignore only generated UUIDs/timestamps, including their HTML excerpt."""
    import re

    content = re.sub(
        r'((?:"|&quot;)serialNumber(?:"|&quot;):\s*(?:"|&quot;))urn:uuid:[0-9a-f-]{36}',
        r"\1urn:uuid:GENERATED",
        content,
    )
    return re.sub(
        r'((?:"|&quot;)timestamp(?:"|&quot;):\s*(?:"|&quot;))'
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
        r"\1GENERATED-TIME",
        content,
    )


def _render_svg(primary: dict, baseline: dict) -> str:
    metrics = ["precision", "recall", "f1"]
    bars = []
    x = 60
    for name in metrics:
        p_val = primary[name]["point"] * 200
        b_val = baseline[name]["point"] * 200
        bars.append(f'<rect x="{x}" y="{220 - p_val}" width="30" height="{p_val}" fill="#005fcc"/>')
        bars.append(
            f'<rect x="{x + 40}" y="{220 - b_val}" width="30" height="{b_val}" fill="#888"/>'
        )
        p_text = f"{primary[name]['point']:.3f}"
        b_text = f"{baseline[name]['point']:.3f}"
        bars.append(f'<text x="{x}" y="240" font-size="11">{name}</text>')
        bars.append(f'<text x="{x}" y="252" font-size="9">P {p_text} / B {b_text}</text>')
        x += 120
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="420" height="340" role="img">
<title>Provisional fixture agreement across four authored projects</title>
<rect width="100%" height="100%" fill="#fff"/>
<text x="20" y="24" font-size="14">Algorithm presence by location (fixture corpus)</text>
<text x="20" y="44" font-size="11">Blue: pqc-readiness | Grey: regex baseline</text>
{"".join(bars)}
<text x="20" y="280" font-size="10">
n=4 authored projects; 13 provisional labels; seed=42; B=1000</text>
<text x="20" y="295" font-size="10">
Four-project bootstrap is fixture resampling, not generalization.</text>
<text x="20" y="310" font-size="10">
F1 intervals: P [{primary["f1"]["lower"]:.3f}, {primary["f1"]["upper"]:.3f}]
/ B [{baseline["f1"]["lower"]:.3f}, {baseline["f1"]["upper"]:.3f}]</text>
</svg>"""


if __name__ == "__main__":
    raise SystemExit(main())
