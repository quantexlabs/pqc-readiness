"""Command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pqc_readiness.constants import DEFAULT_TLS_TEST_HOSTS
from pqc_readiness.evaluation.runner import run_evaluation, write_evaluation_results
from pqc_readiness.models import SensitivityClass
from pqc_readiness.pipeline import PipelineConfig, run_pipeline, write_pipeline_outputs


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-readiness",
        description="Post-quantum migration readiness assessment with CycloneDX CBOM output",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run inventory scan and generate reports")
    scan.add_argument(
        "--tls-host",
        action="append",
        default=[],
        help="TLS host to scan (repeatable; defaults to badssl.com test hosts)",
    )
    scan.add_argument("--code-dir", type=Path, help="Directory of source code to scan")
    scan.add_argument("--config-dir", type=Path, help="Directory of config files to scan")
    scan.add_argument(
        "--cert",
        type=Path,
        action="append",
        default=[],
        help="X.509 certificate path",
    )
    scan.add_argument("--known-hosts", type=Path, help="SSH known_hosts file")
    scan.add_argument(
        "--sensitivity",
        choices=[s.value for s in SensitivityClass],
        default=SensitivityClass.UNCLASSIFIED.value,
    )
    scan.add_argument("--lifetime-years", type=int, default=10)
    scan.add_argument("--no-harvest-exposure", action="store_true")
    scan.add_argument("--skip-tls", action="store_true", help="Skip TLS network scanning")
    scan.add_argument("--output-dir", type=Path, default=Path("results/latest"))
    scan.add_argument("--project-name", default="pqc-readiness-scan")
    scan.add_argument(
        "--require-inputs",
        action="store_true",
        help="Exit with an error when requested local inputs are missing",
    )

    evaluate = sub.add_parser("evaluate", help="Run evaluation against ground truth corpus")
    evaluate.add_argument(
        "--corpus-dir",
        type=Path,
        default=Path("data/evaluation/corpus"),
    )
    evaluate.add_argument(
        "--ground-truth",
        type=Path,
        default=Path("data/evaluation/ground_truth.yaml"),
    )
    evaluate.add_argument("--seed", type=int, default=42)
    evaluate.add_argument("--n-bootstrap", type=int, default=1000)
    evaluate.add_argument(
        "--output",
        type=Path,
        default=Path("results/evaluation/primary.json"),
    )

    pipeline = sub.add_parser("pipeline", help="One-command scan plus evaluation")
    pipeline.add_argument("--output-dir", type=Path, default=Path("results/latest"))
    pipeline.add_argument("--skip-tls", action="store_true")
    pipeline.add_argument("--skip-eval", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        hosts = tuple(args.tls_host) if args.tls_host else DEFAULT_TLS_TEST_HOSTS
        config = PipelineConfig(
            tls_hosts=hosts,
            code_dir=args.code_dir,
            config_dir=args.config_dir,
            cert_paths=tuple(args.cert),
            known_hosts=args.known_hosts,
            sensitivity=SensitivityClass(args.sensitivity),
            lifetime_years=args.lifetime_years,
            harvest_exposure=not args.no_harvest_exposure,
            output_dir=args.output_dir,
            project_name=args.project_name,
            skip_tls=args.skip_tls,
            require_inputs=args.require_inputs,
        )
        scan = run_pipeline(config)
        paths = write_pipeline_outputs(scan, config)
        print(json.dumps({k: str(v) for k, v in paths.items()}, indent=2))
        if scan.errors or scan.coverage.to_dict()["status"] == "partial":
            return 2
        if not scan.findings and not scan.scan_targets:
            return 1
        return 0

    if args.command == "evaluate":
        _, payload = run_evaluation(
            args.corpus_dir,
            args.ground_truth,
            seed=args.seed,
            n_bootstrap=args.n_bootstrap,
        )
        write_evaluation_results(payload, args.output)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "pipeline":
        config = PipelineConfig(
            output_dir=args.output_dir,
            corpus_dir=Path("data/evaluation/corpus"),
            skip_tls=args.skip_tls,
        )
        scan = run_pipeline(config)
        paths = write_pipeline_outputs(scan, config)
        if not args.skip_eval:
            _, payload = run_evaluation(
                Path("data/evaluation/corpus"),
                Path("data/evaluation/ground_truth.yaml"),
            )
            eval_path = args.output_dir / "evaluation.json"
            write_evaluation_results(payload, eval_path)
            paths["evaluation"] = eval_path
        print(json.dumps({k: str(v) for k, v in paths.items()}, indent=2))
        if scan.errors or scan.coverage.to_dict()["status"] == "partial":
            return 2
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
