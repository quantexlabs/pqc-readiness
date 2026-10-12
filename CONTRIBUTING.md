# Contributing

1. Install tested dev dependencies: `pip install -c requirements-dev.txt -e ".[dev]"`.
2. Run `ruff check src tests scripts data`, `mypy src`, and `pyright` in that environment.
3. Run `pytest --cov=pqc_readiness --cov-report=term-missing --cov-fail-under=90`.
4. Run `python scripts/regenerate_results.py --check` before rewriting artifacts.
5. Regenerate with `python scripts/regenerate_results.py`; it also updates integrity hashes.
6. Do not commit credentials, private keys or local file paths.

Current labels are authored fixtures. Independent adjudication is required before
external-validation claims. Use `data/evaluation/adjudication_sheet.csv` for human review.
