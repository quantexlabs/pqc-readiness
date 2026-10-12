# pqc-readiness documentation

## Quick start

Requires a checkout (fixtures under `data/`).

```bash
pip install -c requirements-dev.txt -e ".[dev]"
pqc-readiness pipeline --skip-tls
```

Regenerate evaluation:

```bash
python scripts/regenerate_results.py
```

## Concepts

- **CBOM:** CycloneDX 1.6 cryptography bill of materials (`results/latest/inventory.cbom.json`)
- **Migration plan:** In-house priority heuristic using CCCS ITSM.40.001 milestone dates
- **Report:** HTML summary with coverage counts (`results/latest/report.html`)

## API

```python
from pathlib import Path
from pqc_readiness.pipeline import PipelineConfig, run_pipeline, write_pipeline_outputs

config = PipelineConfig(corpus_dir=Path("data/evaluation/corpus"), skip_tls=True)
scan = run_pipeline(config)
write_pipeline_outputs(scan, config)
```

## Results

See [RESULTS.md](../RESULTS.md), [data manifest](../data/DATA_MANIFEST.md), and [technical report](technical-report.md).

## Checks

CI is set up to run the tests, type checks, the schema check and the regeneration check on Python 3.11 and 3.12. These are software checks. They do not validate the method.
