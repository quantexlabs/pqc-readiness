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
| docs/PRIOR_ART.md | Bounded public capability references | Documentation CC BY 4.0; immutable upstream README links; no competitor execution or benchmark claim |
| badssl.com | Optional permitted test target | No endpoint content bundled or redistributed |

File hashes for data and generated results are in CHECKSUMS.json. They show file identity, not ownership. No restricted external data is bundled. The local schema copy is checked for syntax only. No tool that reads CBOM files has been tested with this output.
