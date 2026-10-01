# Publication fix report, round 4

2026-10-01. Baseline: `bac281bc3838dcd0a725c5dc2c8393cdea2166ea`.
The independent review remains local and excluded from commits. No push or publication.

The supported result is a **limited fixture-based engineering work sample**. Independent
held-out adjudication, cryptographic/policy review, independent CBOM consumer ingestion
and an independently reviewed real-world case study remain unverified. Findings 1 and
11 are resolved by reducing the publication scope, not by inventing missing validation.
Release as a validated flagship remains blocked.

## Regressions and verification

[Version-pinned baseline replay](../evidence/r4/before-summary.json): 26 R4 checks,
24 failed and 2 already passed. Only the new test file was supplied to an unchanged
archive of the baseline. Its SHA-256 is recorded for exact replay. A separate integrity
mutation test also failed before: the old checker accepted a changed provenance file
with stale hashes. Full original outputs are retained privately; public receipts redact
local coordinates, quoted private audit content and dynamically constructed test tokens.

Both Python 3.11.15 and 3.12.12 pass **144 tests, with 1 skipped** and **91.16% combined
statement/branch coverage**. This is `(1117 + 327) / (1192 + 392)`: statements 93.71%,
branches 83.42%. The skipped test requires explicit opt-in for live TLS; it is not a
successful live scan. Ruff, strict Mypy and configured strict Pyright pass. Coverage
is a regression measure, not cryptographic discovery or policy accuracy.

[Clean-checkout matrix](../evidence/r4/clean-checkout.json) records tests and `--check`
before any regeneration writes, then one-command regeneration and normalized equality
under both runtimes. [Regeneration comparison](../evidence/r4/regeneration.json) records
all eight normalized artifacts matching across runtimes. Only CBOM UUIDs/timestamps and
their HTML excerpt vary; raw integrity hashes are checked separately and refreshed by
the same command. [Schema receipt](../evidence/r4/schema-validation.json) separates the
pinned official-source validation from derivative checks and consumer interoperability.

## Numbered finding ledger

Each listed R4 test has a recorded failing-before case. Additional already-correct
mixed-list cases remain explicit rather than being counted as repaired defects.
The JSON [ledger](../evidence/r4/finding-ledger.json) preserves the file/line/test/output
mapping. Before output is in the baseline receipt; after output is in the clean matrix.

| Finding | Disposition and bounded change | File/line evidence | Regression test | Before/after output |
|---|---|---|---|---|
| 1 | narrowed/open external gate: Fixture work sample; no independent case study, held-out adjudication, policy review or consumer ingestion claimed. | `README.md:4` | `tests/test_publication_r4.py:28` (`test_finding_1_work_sample_ceiling`) | 1 failed -> 1 passed; external validation remains open |
| 2 | repaired: Stable math.fsum means, tested dependency constraints, prewrite checks on both runtimes, and regenerated raw integrity hashes. | `src/pqc_readiness/evaluation/metrics.py:82`; `scripts/regenerate_results.py:115` | `tests/test_publication_r4.py:35` (`test_finding_2_stable_aggregation_and_constraints`) | 1 failed -> 1 passed; baseline 3.12 --check exit 1 -> candidate exit 0 |
| 3 | repaired: Configuration text cannot receive SAFE/monitor; classification precedes neutral display labels. Unsupported, inactive and mixed tokens retain actionable status. | `src/pqc_readiness/scanners/config.py:82` | `tests/test_publication_r4.py:54` (`test_finding_3_config_requires_verification`) | 4 failed, 2 already passed -> all 6 passed; verification actions retained |
| 4 | repaired: Per-file failures retain findings before and after failure, count two successful reads rather than three attempts, and report sanitized file coordinates. | `src/pqc_readiness/scanners/codebase.py:150`; `src/pqc_readiness/scanners/config.py:143` | `tests/test_publication_r4.py:71` (`test_finding_4_retain_successes_around_failure`) | 4 failed -> 4 passed; two findings/read files and one file failure per scenario |
| 5 | repaired with explicit identity exception: Private originals preserved; public excerpts sanitized; temporary test coordinates and all reachable text/commit metadata screened. Requested human identity and required upstream notices retained; no anonymous-metadata claim. | `scripts/verify_publication.py:56`; `tests/test_publication_r3.py:109` | `tests/test_publication_r4.py:102` (`test_finding_5_public_text_hygiene`) | 1 failed -> 1 passed; 6 additional quoted-text/metadata/history regressions fail before and pass after |
| 6 | repaired syntax/provenance gate; consumer gate open: Rebased on pinned official source, vendored both references, verified exact two-annotation-only difference and separate official/derivative fixture validation. Formats remain annotations. | `data/schemas/PROVENANCE.md:6`; `scripts/validate_schema.py:78` | `tests/test_publication_r4.py:117` (`test_finding_6_pinned_schema_lineage`) | 1 failed -> 1 passed; official hash/equality pass and zero fixture errors on both runtimes |
| 7 | repaired/preserved qualifications: 10 MiB units and eager traversal limit explicit. Unpinned early replay count withdrawn; macro/pooled fixture qualifications and authored-policy limits retained. | `README.md:71`; `RESULTS.md:11` | `tests/test_publication_r4.py:127` (`test_finding_7_units_and_replay_ceiling`) | 1 failed -> 1 passed; no independent performance/policy claim |
| 8 | repaired/preserved modest contribution: Immutable prior-art README references and exact unofficial milestone header; no competitor run, novelty or endorsement claim. | `docs/PRIOR_ART.md:9`; `src/pqc_readiness/report/html.py:112` | `tests/test_publication_r4.py:142` (`test_finding_8_bounded_header_and_prior_art`) | 1 failed -> 1 passed |
| 9 | repaired scan contract; bounded result: Final-ref credential/private-key pattern scan, redacted matches, historical deleted blobs and sensitive export warning. No rotation indicated by the bounded evidence. | `scripts/verify_publication.py:29`; `README.md:61` | `tests/test_publication_r4.py:187` (`test_finding_9_secret_audit_contract`) | 1 failed -> 1 passed; synthetic token rejected without echoing it; final candidate has no matching secret |
| 10 | repaired: Complete Apache copies include the standard appendix and retain respective copyright notices; scope map separates software, documentation and third-party schemas. Hashes identify bytes, not ownership. | `LICENSE:193`; `data/schemas/LICENSE:193`; `LICENSING.md:1` | `tests/test_publication_r4.py:251` (`test_finding_10_complete_licenses`) | 1 failed -> 1 passed |
| 11 | presentation repaired; independent case-study gate open: Owner workflow and traceable fixture example, observations caption, concise actual-input workflow row and public release evidence table. No client delivery or independent case study invented. | `README.md:41`; `src/pqc_readiness/report/html.py:70` | `tests/test_publication_r4.py:259` (`test_finding_11_traceable_owner_workflow`) | 1 failed -> 1 passed; actual-policy-input regression also fails before and passes after |

The supplemental `tests/test_regeneration_r4.py:13` test changes provenance text without
changing generated metrics and requires `--check` to reject stale integrity hashes.
`tests/test_schema_r4.py` checks missing references, derivative/fingerprint drift, and
actual offline SPDX/JSF shape validation. The synthetic JSF shape is not a verified
signature. JSON Schema `format` values remain annotations; URI/date/certificate/signature
semantics are not asserted. Exact comparison with official source allows only the two
documented descriptive annotation changes, rather than inferring equality from a broad
annotation-stripping fingerprint.

## Reproduce

Use a checkout and Python 3.11 or 3.12 with the tested constraints:

```bash
pip install -c requirements-dev.txt -e '.[dev]'
python scripts/regenerate_results.py --check
pytest --cov=pqc_readiness --cov-report=term-missing --cov-fail-under=90
ruff check src tests scripts data
mypy src
pyright
python scripts/validate_schema.py
python scripts/regenerate_results.py
python scripts/regenerate_results.py --check
python scripts/verify_publication.py --ref publication-r4
```

Pyright must use the selected dependency environment; the recorded matrix supplies
`--pythonpath` explicitly. Network dependency acquisition was unavailable locally.
Python 3.12 dependencies were installed from the existing package cache with exactly
the committed runtime/development pins; Python 3.11 used the matching local environment.
Both editable installation and wheel construction are checked using local build tools.
These receipts do not claim a fresh network installation or remote CI execution.

For official-source replay, fetch the immutable source URL in
`data/schemas/provenance.json`, verify its recorded SHA-256, then run
`python scripts/validate_schema.py --official-source verified-upstream.json`.
The exact original source bytes are retained privately; the public derivative removes
named descriptive examples and retains upstream attribution/modification notice.

## Candidate and delivery audit

The current instruction authorizes the requested named human author/committer identity;
the candidate does not claim zero personal metadata. Required upstream attribution is
also retained. New commit messages contain no attribution trailer. The final-ref audit
screens every reachable tracked text blob, filename and commit author/committer/message,
including tests and quoted logs, for the declared hygiene and credential patterns.
No secret matches were found in that bounded candidate scan. It does not prove absence
of arbitrary concealed secrets, establish ownership, or inspect remote/private refs.

The original source history is preserved. A separate one-root `publication-r4` branch
contains the sanitized candidate, following the round 3 content-only procedure. The
companion delivery receipt binds exact source/candidate commits, candidate tree, tested
content and bundle digest. Local Git writes were denied; the authorized commits and
verified fallback bundles were built in a temporary repository. The combined private
fallback also carries the source-history branch and must not be published wholesale.
A separate single-ref publication bundle is supplied for the bounded candidate. None
of these artifacts is a push, deployment or publication receipt.

The fallback is `state/r4.bundle`, containing the preserved source-history branch and
the separate one-root `publication-r4` branch. `state/publication-r4.bundle` contains
only the sanitized candidate. `state/r4-delivery.json` records their exact refs,
identities, checksums, verification and final-ref audit. The clean-checkout receipt
defines its content digest explicitly and excludes only the R4 receipts and this
report to avoid self-reference; final bundle replay verifies the complete candidate.
