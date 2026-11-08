"""Tests for the text, JSON and Markdown renderers plus the CI exit codes."""

from __future__ import annotations

import json

from rbacpath.escalate import analyse_all, find_paths
from rbacpath.model import Subject
from rbacpath.report import (
    exit_code,
    render_json,
    render_markdown,
    render_text,
    sort_results,
)


def load(path: str):
    from rbacpath.model import load_cluster

    with open(path, "r", encoding="utf-8") as handle:
        return load_cluster(handle.read())


class TestTextReport:
    def test_header_counts_are_consistent(self, sample_cluster):
        results = analyse_all(sample_cluster)
        text = render_text(results)
        privileged = sum(1 for r in results if r.findings)
        assert f"subjects analysed: {len(results)}" in text
        assert f"privileged: {privileged}" in text

    def test_clean_input_says_so(self, sample_cluster):
        result = find_paths(sample_cluster, Subject("serviceaccount", "monitor", "staging"))
        text = render_text([result])
        assert "No escalation path found" in text

    def test_paths_show_rule_and_binding(self, sample_cluster):
        results = analyse_all(sample_cluster)
        text = render_text(results)
        assert "ClusterRoleBinding/" in text or "RoleBinding/" in text
        assert "rule:" in text

    def test_max_paths_is_respected(self, sample_cluster):
        results = analyse_all(sample_cluster)
        text = render_text(results, max_paths=1)
        subject_blocks = [line for line in text.splitlines() if line.startswith("CRITICAL")]
        assert subject_blocks

    def test_clean_subjects_are_listed_separately(self, sample_cluster):
        results = analyse_all(sample_cluster)
        text = render_text(results)
        assert "No escalation path" in text


class TestJsonReport:
    def test_json_is_valid_and_structured(self, sample_cluster):
        results = analyse_all(sample_cluster)
        payload = json.loads(render_json(results))
        assert payload["tool"] == "rbacpath"
        assert payload["summary"]["subjects"] == len(results)
        assert payload["summary"]["findings"] == sum(len(r.findings) for r in results)

    def test_hop_dicts_carry_provenance(self, sample_cluster):
        results = analyse_all(sample_cluster)
        payload = json.loads(render_json(results))
        hop = None
        for subject in payload["subjects"]:
            for finding in subject["findings"]:
                for candidate in finding["hops"]:
                    if candidate["primitive"] == "impersonate":
                        hop = candidate
        assert hop is not None
        assert hop["role"]
        assert hop["binding"]
        assert hop["rule"]

    def test_compact_mode_is_single_line(self, sample_cluster):
        results = analyse_all(sample_cluster)
        payload = render_json(results, pretty=False)
        assert "\n" not in payload

    def test_cluster_admin_count_is_present(self, sample_cluster):
        payload = json.loads(render_json(analyse_all(sample_cluster)))
        assert payload["summary"]["cluster_admin_paths"] >= 1


class TestMarkdownReport:
    def test_markdown_has_table_and_headings(self, sample_cluster):
        md = render_markdown(analyse_all(sample_cluster))
        assert md.startswith("## rbacpath report")
        assert "| Subject | Terminal |" in md
        assert "### " in md

    def test_markdown_clean_case(self, sample_cluster):
        result = find_paths(sample_cluster, Subject("serviceaccount", "monitor", "staging"))
        md = render_markdown([result])
        assert "No escalation path found" in md


class TestExitCode:
    def test_any_gate_fails_on_findings(self, sample_cluster):
        results = analyse_all(sample_cluster)
        assert exit_code(results) == 2
        assert exit_code(results, fail_on="any") == 2

    def test_critical_gate_passes_namespace_only(self):
        from rbacpath.escalate import Finding, Hop, PathResult

        hop = Hop(
            primitive="secrets-read",
            title="Read secrets",
            detail="",
            scope="prod",
            role_ref="Role/prod/r",
            binding_ref="RoleBinding/prod/b",
            rule_text="get on secrets",
            confidence="medium",
            severity="HIGH",
        )
        result = PathResult(
            subject="user:x",
            findings=[
                Finding(
                    subject="user:x",
                    terminal="namespace_admin",
                    scope="prod",
                    severity="HIGH",
                    confidence="medium",
                    hops=[hop],
                )
            ],
        )
        assert exit_code([result], fail_on="critical") == 0
        assert exit_code([result], fail_on="any") == 2

    def test_none_gate_always_passes(self, sample_cluster):
        assert exit_code(analyse_all(sample_cluster), fail_on="none") == 0

    def test_clean_input_passes(self, sample_cluster):
        result = find_paths(sample_cluster, Subject("serviceaccount", "monitor", "staging"))
        assert exit_code([result]) == 0


class TestSorting:
    def test_sort_results_puts_critical_first(self, sample_cluster):
        results = sort_results(analyse_all(sample_cluster))
        severities = [r.findings[0].severity for r in results if r.findings]
        assert severities[0] == "CRITICAL"
        assert severities == sorted(
            severities, key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(s, 9)
        )
