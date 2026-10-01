# Licence and data manifest

| Scope | Authorship/source | Licence and evidence |
|---|---|---|
| src/, scripts/, tests/, pyproject and configuration | QuanteX Labs repository-authored software | Apache-2.0, LICENSE |
| All Markdown documentation, including README/RESULTS and docs/ | QuanteX Labs | CC BY 4.0 https://creativecommons.org/licenses/by/4.0/ |
| data/evaluation/corpus/ | Repository-authored fixtures | Apache-2.0; four local classes; no client data |
| data/evaluation/ground_truth.yaml and adjudication_sheet.csv | Provisional repository-authored labels | Apache-2.0; independent authorship/adjudication unverified |
| data/evaluation/regression_cases.json | Repository-authored negative/attribute test cases | Apache-2.0; known alias miss; not held-out validation |
| data/evaluation/corpus/proj_rsa_app/certs/rsa2048.pem | Self-signed test certificate | Apache-2.0; public certificate only; private key not shipped |
| data/schemas/ | Local CycloneDX derivative | Apache-2.0, OWASP Foundation; pinned official revision, derivative notice and hashes in PROVENANCE.md; vendored references |
| results/evaluation/* and results/latest/* | Generated fixture outputs | Apache-2.0; one-command regeneration; runtime separate |
| docs/evidence/r3/ | Sanitized local verification receipts | Apache-2.0 for machine receipts; documentation CC BY 4.0 |
| docs/evidence/r4/ | R4 local publication and runtime receipts | Apache-2.0 for machine receipts; documentation CC BY 4.0; only sanitized public receipts; original local receipts remain private |
| docs/PRIOR_ART.md | Bounded public capability references | Documentation CC BY 4.0; immutable upstream README links; no competitor execution or benchmark claim |
| badssl.com | Optional permitted test target | No endpoint content bundled or redistributed |

File hashes for data and generated results are in CHECKSUMS.json. They establish file
identity, not ownership. Authorship/title are repository declarations, not independently
verified ownership receipts. No restricted external corpus is bundled. Ignored local
reviews, environments, caches, bundles and working logs are excluded from publication.
The companion R4 delivery receipt binds the exact candidate reference and bundle digest.
It is outside the committed tree to avoid a containing-commit self-reference. The local schema derivative
checks syntax only, and consumer ingestion remains unverified.
