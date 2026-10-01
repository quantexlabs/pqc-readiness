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

## Release evidence

The companion delivery receipt binds the exact candidate commit and tree to the
bundle digest. The committed evidence below records the tested content and commands;
it does not embed a hash of its own containing commit.

| Check | Evidence and scope |
|---|---|
| Python 3.11 and 3.12 | [Clean-checkout matrix](evidence/r4/clean-checkout.json); tests with combined statement/branch coverage |
| Deterministic artifacts | [Regeneration comparison](evidence/r4/regeneration.json); eight normalized artifacts and integrity manifest |
| Schema syntax | [Pinned schema receipt](evidence/r4/schema-validation.json); consumer ingestion remains unverified |
| Regression ledger | [Round 4 report](milestones/PUBLICATION_FIX_REPORT_R4_2026-10-01.md); before/after checks and open external gates |

## Historical milestones

- [M0 novelty check](milestones/M0_REPORT.md)
- [M1 retrospective specification](milestones/M1_REPORT.md)
- [M2 implementation](milestones/M2_REPORT.md)
- [M3 evaluation](milestones/M3_REPORT.md)
- [Round 3 publication fix report](milestones/PUBLICATION_FIX_REPORT_R3_2026-10-01.md)
