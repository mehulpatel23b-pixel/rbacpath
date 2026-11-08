"""Output formatting: human-readable text, JSON and Markdown."""

from __future__ import annotations

import json
from typing import Iterable, List, Sequence

from .escalate import Finding, PathResult

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

GLYPHS = {
    "cluster_admin": "[CLUSTER-ADMIN]",
    "node_escape": "[NODE-ESCAPE]",
    "namespace_admin": "[NAMESPACE-ADMIN]",
}


def _result_severity(result: PathResult) -> str:
    if not result.findings:
        return "NONE"
    return min((f.severity for f in result.findings), key=lambda s: SEVERITY_RANK.get(s, 9))


def sort_results(results: Sequence[PathResult]) -> List[PathResult]:
    return sorted(
        results,
        key=lambda r: (
            min((SEVERITY_RANK.get(f.severity, 9) for f in r.findings), default=9),
            r.subject,
        ),
    )


def render_text(
    results: Sequence[PathResult],
    *,
    color: bool = False,
    max_paths: int = 3,
) -> str:
    """Plain-text report, safe to paste into a ticket."""
    ordered = sort_results(results)
    privileged = [r for r in ordered if r.findings]
    lines: List[str] = []

    total_findings = sum(len(r.findings) for r in privileged)
    lines.append("rbacpath report")
    lines.append("=" * 60)
    lines.append(
        f"subjects analysed: {len(ordered)}   "
        f"privileged: {len(privileged)}   findings: {total_findings}"
    )
    lines.append("")

    if not privileged:
        lines.append("No escalation path found for any analysed subject.")
        return "\n".join(lines) + "\n"

    for result in privileged:
        severity = _result_severity(result)
        head = f"{severity:<8} {result.subject}"
        lines.append(head)
        lines.append("-" * 60)
        for finding in result.findings[:max_paths]:
            tag = GLYPHS.get(finding.terminal, "[FINDING]")
            scope = finding.scope or "cluster-wide"
            lines.append(
                f"  {tag} {finding.terminal} ({scope}) "
                f"severity={finding.severity} confidence={finding.confidence}"
            )
            if finding.summary:
                lines.append(f"    why: {finding.summary}")
            for index, hop in enumerate(finding.hops, 1):
                lines.append(f"    {index}. {hop.title}")
                lines.append(
                    f"       rule:   {hop.rule_text} in {hop.role_ref} "
                    f"via {hop.binding_ref}"
                )
                lines.append(f"       scope:  {hop.scope or 'cluster-wide'}")
        lines.append("")

    skipped = [r for r in ordered if not r.findings]
    if skipped:
        lines.append("No escalation path")
        lines.append("-" * 60)
        for result in skipped:
            lines.append(f"  {result.subject}")
        lines.append("")

    return "\n".join(lines)


def render_json(results: Sequence[PathResult], *, pretty: bool = True) -> str:
    payload = {
        "tool": "rbacpath",
        "version": 1,
        "subjects": [r.to_dict() for r in sort_results(results)],
        "summary": {
            "subjects": len(results),
            "privileged": sum(1 for r in results if r.findings),
            "findings": sum(len(r.findings) for r in results),
            "cluster_admin_paths": sum(
                1
                for r in results
                for f in r.findings
                if f.terminal == "cluster_admin"
            ),
        },
    }
    return json.dumps(payload, indent=2 if pretty else None, sort_keys=False)


def render_markdown(results: Sequence[PathResult]) -> str:
    """Markdown suited to a PR comment or a wiki page."""
    ordered = sort_results(results)
    privileged = [r for r in ordered if r.findings]
    out: List[str] = ["## rbacpath report", ""]
    out.append(
        f"**{len(privileged)}** of **{len(ordered)}** subjects can escalate. "
        f"**{sum(len(r.findings) for r in privileged)}** findings."
    )
    out.append("")
    if not privileged:
        out.append("No escalation path found.")
        return "\n".join(out) + "\n"

    out.append("| Subject | Terminal | Scope | Severity | Confidence | Hops |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for result in privileged:
        for finding in result.findings:
            out.append(
                f"| `{result.subject}` | {finding.terminal} | "
                f"{finding.scope or 'cluster-wide'} | {finding.severity} | "
                f"{finding.confidence} | {len(finding.hops)} |"
            )
    out.append("")

    for result in privileged:
        out.append(f"### `{result.subject}`")
        out.append("")
        for finding in result.findings:
            out.append(f"**{finding.terminal}** in `{finding.scope or 'cluster-wide'}`")
            out.append("")
            if finding.summary:
                out.append(finding.summary)
                out.append("")
            for index, hop in enumerate(finding.hops, 1):
                out.append(
                    f"{index}. **{hop.title}** — `{hop.rule_text}` "
                    f"in `{hop.role_ref}` via `{hop.binding_ref}`"
                )
            out.append("")
    return "\n".join(out)


def exit_code(results: Iterable[PathResult], fail_on: str = "any") -> int:
    """CI gate. ``fail_on`` is 'any', 'critical' or 'none'."""
    fail_on = (fail_on or "any").lower()
    if fail_on == "none":
        return 0
    severities = [f.severity for r in results for f in r.findings]
    if not severities:
        return 0
    if fail_on == "critical":
        return 2 if "CRITICAL" in severities else 0
    return 2
