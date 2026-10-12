# pqc-readiness

A QuanteX Labs Inc. research prototype for reviewing cryptographic observations. It runs on four small fixture projects that we wrote: code, configuration, SSH markers and X.509 certificates. TLS scanning is mocked in tests, so live TLS results are not verified. There is no real-world case study. The prototype has no clients, does not show compliance with any standard and is not independently validated. We do not claim research novelty.

## Example

Install from a checkout with Python 3.11 or 3.12:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -c requirements-dev.txt -e '.[dev]'
python scripts/regenerate_results.py
python scripts/regenerate_results.py --check
```

One command regenerates evaluation JSON, the figure, inventory JSON/CBOM, migration
plan, and [sample HTML report](results/latest/report.html). See [results](RESULTS.md),
[data and licences](data/DATA_MANIFEST.md), and [documentation](docs/index.md).
An asset owner can inspect observation status and assumptions, verify operational use
with the vendor, and revise the sensitivity/lifetime defaults before using the plan.

## Checks

CI is set up to run the tests, type checks, the schema check and the regeneration check on Python 3.11 and 3.12. These are software checks. They do not validate the method.

## Asset-owner workflow

1. Review observation status, evidence and failed/skipped inputs in the sample report.
2. Verify operational use, parameters and vendor dependencies with the asset owner.
3. Record sensitivity, lifetime and exposure, then review the unofficial plan.

For example, `data/evaluation/corpus/proj_pqc_app/src/kem.py:2` contains
`ALGORITHM = "ML-KEM-768"`. The fixture observation is a lexical marker with unknown
risk and key size, so its plan action asks the owner to verify parameters and use.
The text does not demonstrate a working key exchange. Default sensitivity is
unclassified, lifetime 10 years and harvest exposure true; these inputs need review.

Installed-package use requires explicit inputs (fixtures are checkout-only):

```bash
pqc-readiness scan --skip-tls --require-inputs --code-dir ./source --output-dir ./report
```

External roots use opaque input slots with relative paths; relocation preserves IDs.
Overlapping independently supplied roots retain distinct slots. Reports retain evidence
lines, certificate subjects and SSH host markers: users must review their content before
sharing. Failure diagnostics omit raw exception text and absolute local paths.

## Limits and policy

Source scanning is regex-based. Comments and strings may be observations; aliases can
be missed. Sizes and operational use stay unknown when unparsed. Markers do not certify
PQC use. No security-strength or NIST-category mapping is asserted by the CBOM exporter.
The local schema derivative checks syntax only; consumer ingestion remains unverified.

Source scans exclude underscore-prefixed files. The source/config traversal eagerly enumerates
a sorted `rglob` result before applying a cap of 5,000 eligible files per
directory, so the cap does not bound traversal memory or time. Each file limit is 10 MiB;
certificate/SSH inputs also enforce 10 MiB limits.
Coverage separates requested targets, artifact targets, projects and successfully read
files; it is not a production completeness percentage. TLS caps at the configured host
limit, uses one handshake without certificate verification, and does not enumerate all
ciphers or hybrid key exchange. Failed/skipped inputs and report limits are displayed;
JSON outputs retain all findings/actions. HTML displays at most 500 findings and 200 actions.

Scoring is an unvalidated in-house heuristic. Its thresholds and rules are repository-authored
and unvalidated. Risk contributes 3 points for vulnerable
and 1 for reduced; lifetime contributes 2 at >=10 years or 1 at >=5; sensitivity contributes
3/2/1/0 for protected B/A, unclassified/public. Explicit confidentiality or key-establishment
use adds 3 for harvest exposure; signature and unknown use add 0. Critical/high/medium/low
thresholds are 7/5/3/below 3. Unknown risk receives medium verification priority; safe
algorithm classification receives monitor. Defaults are unclassified, 10 years, exposure
true, use unknown. These are assumptions, not measured policy accuracy.

The [CCCS roadmap](https://www.cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001)
provides the selected 2031/2035 federal non-classified system milestones. The prototype
does not implement its planning or governance deliverables. Date matching is not domain
validation of the scoring rationale.

## Bounded feature comparison

Sources reviewed 2026-10-01, using immutable README revisions listed in
[PRIOR_ART.md](docs/PRIOR_ART.md); no competitor was executed. [CBOMkit](https://github.com/cbomkit/cbomkit/blob/feace38c0e9b4ea196d8d026bf20476ed0a80a08/README.md)
describes generation, visualization, and policy checks; [Sonar Cryptography](https://github.com/cbomkit/sonar-cryptography/blob/d1d1b8fad50d65e9f06e380e9f632974f32cb7de/README.md)
describes source detection and CBOM export. These sources are capability references,
not version-pinned performance evidence. This prototype integrates local observations
with an unofficial Canadian milestone heuristic. Global novelty and competitive
superiority are unverified.

## Licence

Code, fixtures, labels, tests and generated results: Apache-2.0, QuanteX Labs.
All Markdown documentation: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/),
attribution QuanteX Labs. Third-party schema/licence provenance is in
[data/schemas/PROVENANCE.md](data/schemas/PROVENANCE.md).
