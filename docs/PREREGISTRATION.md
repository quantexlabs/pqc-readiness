# Retrospective evaluation specification

Recorded 2026-10-01. No independently timestamped pre-results registration exists.
The legacy filename is retained for compatibility; its checksum proves content, not chronology.

## Scope

Four repository-authored projects, 13 provisional algorithm-location labels. The primary
and in-tree regex baseline use the same fixture artifact eligibility and a neutral
TLS-CIPHER label for cipher directives. Generator scripts are excluded for both.
The comparison measures lexical/parsed observation agreement, not operational assets,
parameter correctness, policy accuracy, production generalization or competitor performance.
IBM CBOMkit was not attempted; no service or failed-attempt receipt is asserted.

## Procedure

Macro precision, recall and F1 are computed per project, then bootstrapped over projects
with 1,000 resamples, seed 42 (metric seeds 42/43/44), alpha 0.05. Four-project intervals
reflect fixture resampling only. Attribute/negative regression cases include comments,
AES sizes left unparsed, MD5, explicit RSA parameters, a known alias miss and no-crypto code.
They are repository-authored tests, not a new independently labelled held-out corpus.

## Stop rules and disposition

Independent-validation stop rule: **UNMET**. Independent authorship, adjudication, held-out evaluation and policy review are not done. While this rule is unmet, we make no readiness claim and no benchmark claim. Recall below 0.50 would stop fixture accuracy claims. Memory over 12 GB on a measured slice would trigger a redesign. Current resource records cover only tiny local fixtures.

```bash
python scripts/regenerate_results.py
python scripts/regenerate_results.py --check
```
