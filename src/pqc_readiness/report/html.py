"""HTML report generation for CISO-readable output."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from pqc_readiness.models import MigrationPlan, ScanResult


def escape(text: str) -> str:
    """Escape HTML entities."""
    return html.escape(text, quote=True)


def render_report(
    scan: ScanResult,
    plan: MigrationPlan,
    cbom: dict[str, Any],
    *,
    title: str = "Cryptographic observation report",
) -> str:
    """Render an accessible HTML report."""
    scan.coverage.findings_emitted = len(scan.findings)
    scan.coverage.actions_emitted = len(plan.actions)
    scan.coverage.findings_truncated = len(scan.findings) > 500
    finding_rows: list[str] = []
    for f in scan.findings[:500]:
        finding_rows.append(
            "<tr>"
            f"<td>{escape(f.finding_id)}</td>"
            f"<td>{escape(f.source.value)}</td>"
            f"<td>{escape(str(f.metadata.get('observation', 'unknown')))}</td>"
            f"<td>{escape(f.algorithm)}</td>"
            f"<td>{escape(str(f.key_size or ''))}</td>"
            f"<td>{escape(f.quantum_risk.value)}</td>"
            f"<td>{escape(f.migration_priority.value)}</td>"
            f"<td>{escape(f.location)}</td>"
            "</tr>"
        )

    action_rows: list[str] = []
    finding_by_id = {finding.finding_id: finding for finding in scan.findings}
    workflow_rows: list[str] = []
    for action in plan.actions[:200]:
        finding = finding_by_id.get(action.finding_id)
        action_rows.append(
            "<tr>"
            f"<td>{escape(action.finding_id)}</td>"
            f"<td>{escape(action.priority.value)}</td>"
            f"<td>{escape(action.target_milestone.isoformat())}</td>"
            f"<td>{escape(action.action)}</td>"
            f"<td>{escape(action.rationale)}</td>"
            "</tr>"
        )
        if finding is None:
            location = "finding not present in scan"
            observation_status = "unmatched action"
            unknowns = "Confirm the source finding before relying on this action"
            assumptions = "Do not rely on default priority inputs"
        else:
            location = finding.location
            observation_status = str(finding.metadata.get("observation", "unknown"))
            unknowns_list = ["operational use", "vendor dependencies"]
            if finding.key_size is None:
                unknowns_list.insert(0, "parameters")
            unknowns = ", ".join(unknowns_list)
            assumptions = action.rationale
        workflow_rows.append(
            "<tr>"
            f"<td>{escape(action.finding_id)}</td>"
            f"<td>{escape(location)}</td>"
            f"<td>{escape(observation_status)}</td>"
            f"<td>{escape(unknowns)}</td>"
            f"<td>{escape(action.action)}</td>"
            f"<td>{escape(assumptions)}</td>"
            "</tr>"
        )

    summary_items = "".join(f"<li>{escape(k)}: {v}</li>" for k, v in sorted(plan.summary.items()))
    errors = "".join(f"<li>{escape(e)}</li>" for e in scan.errors)
    warnings = "".join(f"<li>{escape(w)}</li>" for w in scan.warnings)
    coverage = scan.coverage.to_dict()
    coverage_items = "".join(
        f"<li>{escape(str(k))}: {escape(str(v))}</li>"
        for k, v in sorted(coverage.items())
        if k not in {"skipped_paths", "failed_paths"}
    )

    return f"""<!DOCTYPE html>
<html lang="en-CA">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{ font-family: system-ui, sans-serif; line-height: 1.5; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 1rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #444; padding: 0.4rem 0.6rem; text-align: left; }}
    th {{ background: #eee; }}
    .risk-vulnerable {{ font-weight: bold; }}
    nav {{ margin-bottom: 1rem; }}
    a:focus-visible, summary:focus-visible {{ outline: 2px solid #005fcc; outline-offset: 2px; }}
  </style>
</head>
<body>
  <header>
    <h1>{escape(title)}</h1>
    <p>Uses selected CCCS milestone dates; priority scoring is unofficial and unvalidated.</p>
    <p>This report is evidence for planning, not a certification.</p>
  </header>
  <nav aria-label="Sections">
    <a href="#summary">Summary</a> |
    <a href="#findings">Findings</a> |
    <a href="#workflow">Asset-owner workflow</a> |
    <a href="#plan">Migration plan</a> |
    <a href="#cbom">CBOM</a>
  </nav>
  <main>
    <section id="summary" aria-labelledby="summary-heading">
      <h2 id="summary-heading">Executive summary</h2>
      <ul>{summary_items or "<li>No priority actions</li>"}</ul>
      <p>Total findings: {len(scan.findings)}. Scan targets: {len(scan.scan_targets)}.</p>
      <h3>Coverage</h3>
      <p>Coverage status: {coverage["status"]}. Local path counts include artifact targets;
      projects and successfully read files are separate units, not a coverage ratio.</p>
      <p>Showing {min(500, len(scan.findings))} of {len(scan.findings)} findings;
      Showing {min(200, len(plan.actions))} of {len(plan.actions)} actions.
      Display limits: 500 findings and 200 actions; full rows are in JSON outputs.</p>
      <p>Static patterns and lexical markers do not prove operational use.
      Key sizes are unknown when unparsed. Source scans exclude underscore-prefixed files;
      source/config scans cap at 5,000 eligible files and 10 MiB per file.
      Sorted traversal eagerly enumerates the tree; this cap does not bound traversal
      memory or time.
      TLS uses one handshake without certificate verification and does not enumerate all
      ciphers or hybrid key exchanges. Priorities are an unvalidated heuristic.</p>
      <ul>{coverage_items}</ul>
      {"<h3>Warnings</h3><ul>" + warnings + "</ul>" if warnings else ""}
      {"<h3>Errors</h3><ul>" + errors + "</ul>" if errors else ""}
    </section>
    <section id="findings" aria-labelledby="findings-heading">
      <h2 id="findings-heading">Cryptographic inventory</h2>
      <table>
        <caption>Cryptographic observations</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Source</th>
            <th scope="col">Observation status</th>
            <th scope="col">Algorithm</th>
            <th scope="col">Key size</th>
            <th scope="col">Quantum risk</th>
            <th scope="col">Priority</th>
            <th scope="col">Location</th>
          </tr>
        </thead>
        <tbody>
          {"".join(finding_rows) if finding_rows else "<tr><td colspan='8'>No findings</td></tr>"}
        </tbody>
      </table>
    </section>
    <section id="workflow" aria-labelledby="workflow-heading">
      <h2 id="workflow-heading">Asset-owner workflow</h2>
      <p>Observations are leads for the asset owner to verify. Confirm the observed
      status, parameters, operational use and vendor dependencies before taking action.
      The example keeps one plan action traceable to its finding and location;
      it does not assert that the observation is active or operational.</p>
      <h3>Observation to verification</h3>
      <table>
        <caption>Observation to verification</caption>
        <thead>
          <tr>
            <th scope="col">Finding</th>
            <th scope="col">Observed location</th>
            <th scope="col">Observation status</th>
            <th scope="col">Unknowns to verify</th>
            <th scope="col">Matching verification action</th>
            <th scope="col">Assumptions to record</th>
          </tr>
        </thead>
        <tbody>
          {"".join(workflow_rows[:1]) if workflow_rows else "<tr><td colspan='6'>No verification actions</td></tr>"}
        </tbody>
      </table>
    </section>
    <section id="plan" aria-labelledby="plan-heading">
      <h2 id="plan-heading">Migration plan</h2>
      <p>Reference: {escape(plan.reference)}</p>
      <table>
        <caption>Recommended actions by priority</caption>
        <thead>
          <tr>
            <th scope="col">Finding</th>
            <th scope="col">Priority</th>
            <th scope="col">Target milestone</th>
            <th scope="col">Action</th>
            <th scope="col">Rationale and assumptions</th>
          </tr>
        </thead>
        <tbody>
          {"".join(action_rows) if action_rows else "<tr><td colspan='5'>No actions</td></tr>"}
        </tbody>
      </table>
    </section>
    <section id="cbom" aria-labelledby="cbom-heading">
      <h2 id="cbom-heading">CycloneDX CBOM excerpt</h2>
      <details>
        <summary>View CBOM JSON (first 8000 characters)</summary>
        <pre>{escape(json.dumps(cbom, indent=2)[:8000])}</pre>
      </details>
    </section>
  </main>
  <footer>
    <p>Generated by pqc-readiness. Numbers in evaluation reports come from reproducible code only.</p>
  </footer>
</body>
</html>
"""


def write_report_html(path: Path, html_content: str) -> None:
    """Write HTML report to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")
