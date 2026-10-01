# Technical report: pqc-readiness

This integration prototype is a Limited engineering work sample. It aggregates
observations from four local artifact classes, with a separately mocked TLS scanner,
into JSON, a CycloneDX-style CBOM, and an HTML verification plan. It demonstrates
fixture engineering only. See [README](../README.md)
for policy assumptions, scope limits and related-work links, and [RESULTS](../RESULTS.md)
for regenerated provisional macro metrics.

The fixture report currently contains 13 cryptographic observations and 12 owner
verification actions. Each action points back to an observed location and records the
status or unknowns that the asset owner must verify. No independently reviewed
real-world case study is included.

Static names and markers do not prove operational use. Parameters remain unknown when
unparsed; no security-strength/category table is asserted. Syntax validation uses a
clearly marked local schema derivative. Independent consumer ingestion, cryptographic
semantic review and policy scenario review have not been demonstrated.

The evaluation specification is retrospective. Independent label authorship and
adjudication are unverified, and the independent-validation stop rule remains unmet.
There is no held-out corpus or established-tool comparison. Four-project bootstrap
intervals quantify fixture resampling, not future-repository uncertainty. Attribute and
negative cases are separately tested, including an explicitly documented alias miss.

The contribution is a lightweight integration of observations and selected federal
milestone dates. Prior tools already supply detection, export, visualization and policy
checks. Global novelty, buyer-demand trends and competitive performance are unverified.
No client-performance claim is supported. No client data is bundled.

Immutable capability references for CBOMkit and Sonar Cryptography are listed in
[PRIOR_ART.md](PRIOR_ART.md). No competitor was executed.

Written documentation CC BY 4.0; attribution QuanteX Labs.
