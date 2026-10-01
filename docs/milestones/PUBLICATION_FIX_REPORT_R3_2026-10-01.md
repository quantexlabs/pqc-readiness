# Publication fix report, round 3

Date: 2026-10-01. Scope: local repair of the round 2 publication review.
Baseline: `c559c457a919a7b2a08d410e520ce989d0951a00`. The review files remain local,
ignored and uncommitted. No push or publication occurred.

The supported outcome is a **fixture integration prototype**, not a validated flagship.
Independent adjudication, a licensed held-out evaluation, domain review of policy/CBOM
semantics, independent consumer ingestion, and exact upstream-schema lineage remain
unverified. Readiness/independent-benchmark claims stop; provisional engineering
regressions continue. This is an explicit resolution by shrinking claims, not a claim
that missing external validation was performed.

## Regression evidence

[Before replay](../evidence/r3/before-summary.json): 30 new checks against the original
snapshot, 26 fail and 4 pass; [failure output](../evidence/r3/before-expanded.txt).
The earlier small replay is not used as independently replayable evidence; its exact test version was not pinned.
New case input JSON was supplied for the replay; original implementation/docs remained
unchanged. INFO findings 1 and 14 require preservation/audit, not a fabricated failing
assertion. Every repair/claim shrink below has a pre-failing check or an explicit
history audit failure; continuing validity gates are stated separately.

[After full suite](../evidence/r3/tests.txt): **112 passed, 1 skipped; combined
statement/branch coverage 91.34%**. Live TLS is an explicit opt-in test requiring actual
findings and zero errors; it is skipped locally, not counted as successful validation.
[Ruff](../evidence/r3/ruff.txt), [Mypy](../evidence/r3/mypy.txt),
[Pyright](../evidence/r3/pyright.txt) cover configured scope; all pass.
[Environment](../evidence/r3/environment.json), [dependencies](../evidence/r3/dependencies.txt),
[whole-process resources](../evidence/r3/resources.json). Local Python 3.11 only;
no remote CI/Python 3.12 result or fresh network dependency installation is claimed.
Coverage is a regression exercise measure, not cryptographic/policy validation.

## Finding ledger

| Finding | Disposition and evidence file/line | Test | Before/after output and ceiling |
|---|---|---|---|
| 1 | Preserved INFO result; no defect to manufacture. `pyproject.toml:55` | Full suite and configured static checks | 112 pass; 1 live skip; 91.34%; clean static checks. |
| 2 | Repaired external path identity; explicit scan roots and opaque input slots. `src/pqc_readiness/pipeline.py:43` | `tests/test_publication_r3.py:43`; `tests/test_publication_r3.py:166` | Before loses findings/IDs; after preserves 2 source findings and 5 cert/SSH observations across relocation. |
| 3 | Unparsed sizes stay unknown; MD5 no longer emits SHA-1; markers require verification. `src/pqc_readiness/scanners/codebase.py:63` | `tests/test_publication_r3.py:58`; `tests/test_publication_r3.py:68`; `tests/test_publication_r3.py:158` | Before invented AES-256, safe marker, spurious SHA-1; after null size, unknown marker, MD5 only; 7 attribute/negative cases pass. |
| 4 | Use is explicit or unknown; confidentiality/key-establishment harvest bonus is 3; signature/unknown 0. `src/pqc_readiness/classification/priority.py:59` | `tests/test_publication_r3.py:82`; `tests/test_publication_r3.py:223` | Before signature critical/confidentiality high; after signature medium/confidentiality critical for the fixed scenario. Domain review unverified; heuristic claim shrunk. |
| 5 | Omitted strength/category assertions and guessed execution/platform/function fields; KEM primitive fixed; certificate issuer retained. `src/pqc_readiness/cbom/builder.py:48` | `tests/test_publication_r3.py:90`; `tests/test_publication_r3.py:235`; `tests/test_publication_r3.py:248` | Before invented categories and KEM key-agree; after kem, no strengths, full fixture syntax validation passes. Cryptographic review/consumer ingestion remain unverified. |
| 6 | Retrospective specification; unmet stop rule explicit. Shared comparator eligibility and neutral cipher-directive vocabulary. `src/pqc_readiness/evaluation/eligibility.py:14`; `docs/PREREGISTRATION.md:1` | `tests/test_publication_r3.py:100`; release claim contract (6) | Before baseline scans excluded generator and independence asserted; after generator excluded for both, 13 provisional labels. Baseline F1 now 0.765. No adjudication, held-out corpus or prospective record invented. |
| 7 | Original history preserved privately. Separately prepared content-only publication candidate; new commits use requested named identity and contain no attribution trailer. `scripts/verify_publication.py:12`; `data/schemas/PROVENANCE.md:3` | release claim contract (7); publication Git/tree audit | Source-history audit fails inherited trailer; candidate audit must pass. Current user instruction supersedes older anonymity requirement. Local schema derivative pinned to known source blob; upstream lineage remains unverified. |
| 8 | Replaced stale internal report with self-contained evidence index; no private review links or em dash. `REPORT.md:1` | release claim contract (8); tracked-file audit | Before old counts and private review link; after current R3 evidence and bounded status. |
| 9 | Failures use sanitized scan coordinates and exception types, preserving partial errors. `src/pqc_readiness/pipeline.py:53` | `tests/test_publication_r3.py:107` | Before absolute home path in exported failure; after all four failure outputs contain no absolute home path. |
| 10 | Separated targets/projects/read files; structured malformed/TLS/cap failures; displayed/total rows and partial CLI exit. `src/pqc_readiness/coverage.py:38`; `src/pqc_readiness/report/html.py:18` | `tests/test_publication_r3.py:119`; `tests/test_publication_r3.py:129`; `tests/test_publication_r3.py:191`; `tests/test_publication_r3.py:200` | Before malformed certificate crashes, TLS failure uncounted, rows silently capped; after 2 failed inputs, explicit 500/501 and 200/501 display, 1 requested/scanned target, 4 projects, 7 files. Live success unverified. |
| 11 | All 8 artifacts regenerate together; stale primary fixed; timing separated into whole-command receipts; CI rejects normalized diffs. `scripts/regenerate_results.py:52`; `scripts/measure_resources.py:18` | `tests/test_publication_r3.py:258`; release claim contract (11) | Before --check ignored stale content; after check passes current artifacts and exits 1 after evidence mutation. Receipt has three runs per command; only generated serial/timestamp fields ignored. |
| 12 | Four local classes plus separately mocked TLS. Integration contribution; no independent-benchmark, novelty or competitive-performance claim. `README.md:4` | release claim contract (12) | Before all-five/independence overclaims; after bounded scope. Moving prior-art README links are described as unpinned, unmeasured sources. |
| 13 | Unambiguous licence map; retained OWASP full licence; exact local schema source/hash/modification; data and both result directories hashed. `data/DATA_MANIFEST.md:12`; `data/schemas/PROVENANCE.md:8` | release claim contract (13); schema-source notice/hash | Before missing result/licence/provenance scope; after declared map and source identities. Upstream revision and copyright title independently unverified, so no authenticity/title assurance. |
| 14 | Preserved INFO finding: no rotation indicated; rechecked exact candidate file set and available messages. `scripts/verify_publication.py:33` | Publication tracked-file/history audit | No private-key headers found; archive excludes local reviews/caches. Bounded check is not proof about concealed secrets or remote history. |
| 15 | Lead with prototype capability and outstanding gates; report observation confidence, unknowns, partial coverage, action assumptions and vendor verification. `README.md:9`; `src/pqc_readiness/report/html.py:122` | release claim contract (15); external/marker/plan regressions | Before flagship implication; after fixture work sample. No independent validation, consumer ingestion, official compliance or firm client delivery implied. |

## Reproduction and delivery

```bash
python scripts/regenerate_results.py
python scripts/regenerate_results.py --check
pytest --cov=pqc_readiness --cov-report=term-missing --cov-fail-under=90
ruff check src tests scripts data
mypy src
pyright
```

One command produces eight deterministic/normalized fixture artifacts. Raw CBOM UUIDs
and timestamps vary; metrics and substantive evidence must match. Stale-evidence mutation
is rejected with exit 1. The clean-checkout receipt records regeneration followed by
`--check`, only generated UUID/timestamp differences in tracked status, full tests and a wheel build using available local
dependencies. Only tracked candidate files are copied, never the whole working directory.

This is a historical engineering record. Current release evidence is in
[round 4](PUBLICATION_FIX_REPORT_R4_2026-10-01.md). Original receipts are retained
privately; public historical excerpts sanitize local coordinates and quoted audit text.
The older upstream-schema gate is superseded only by the pinned R4 syntax receipt.
Independent validation, domain review and consumer ingestion remain unverified.
