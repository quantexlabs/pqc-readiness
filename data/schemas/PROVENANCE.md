# CycloneDX schema provenance

This directory contains a local CycloneDX 1.6 JSON Schema derivative and the
schemas required to validate it offline.

The upstream source is pinned to
`https://raw.githubusercontent.com/CycloneDX/specification/55343ba19dee1785acf1ce9191540d5fd7b590db/schema/bom-1.6.schema.json`.
The pinned upstream revision is
`55343ba19dee1785acf1ce9191540d5fd7b590db`; the source receipt records
SHA-256
`3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93`.
The previous unknown-source lineage has been retired.

The local derivative carries this exact modification notice in its `$comment`:

> CycloneDX JSON schema is published under the terms of the Apache License 2.0. Local modification by QuanteX Labs on 2026-10-01: removed named model examples from the modelArchitecture description; validation rules unchanged.

The change removes named examples from one descriptive field only. It does not
change validation keywords or constraints. `scripts/validate_schema.py`
recomputes a constraint-only fingerprint, checks all local references, and can
validate the committed CBOM fixture. Consumer ingestion remains unverified:
schema syntax and fixture validation do not establish downstream consumer
semantic compatibility.

The external references used by the BOM schema are vendored beside it:
`spdx.schema.json` and `jsf-0.82.schema.json`. Their original Apache-2.0
notices are retained in `data/schemas/LICENSE`. `provenance.json` records each
reference's pinned URL, revision, upstream SHA-256, and local SHA-256; the
recorded upstream and local digests match for both vendored files.

JSON Schema `format` values are annotations here; no format checker is enabled.
The syntax receipt does not assert URI/date/certificate/signature semantics.
