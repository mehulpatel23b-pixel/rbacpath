"""End-to-end CLI tests: argument handling, formats, exit codes, stdin."""

from __future__ import annotations

import io
import json
import os
import sys
import contextlib

import pytest

from rbacpath.cli import build_parser, main


def run_cli(argv, stdin_text=None):
    """Run main() capturing stdout/stderr."""
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
    finally:
        sys.stdin = old_stdin
    return code, out.getvalue(), err.getvalue()


class TestCliBasics:
    def test_no_args_prints_help_and_fails(self):
        code, out, err = run_cli([])
        assert code == 1
        assert "rbacpath" in err

    def test_help_exits_zero(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(["--help"])
        assert excinfo.value.code == 0

    def test_version_flag(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(["--version"])
        assert excinfo.value.code == 0

    def test_missing_file_is_an_error(self):
        code, out, err = run_cli(["does-not-exist.yaml"])
        assert code == 1
        assert "cannot read" in err

    def test_empty_rbac_input_is_an_error(self, tmp_path):
        path = tmp_path / "empty.yaml"
        path.write_text("kind: Service\nmetadata:\n  name: nope\n", encoding="utf-8")
        code, out, err = run_cli([str(path)])
        assert code == 1
        assert "no Role" in err


class TestCliAnalysis:
    def test_text_mode_runs_and_gates(self, export_path):
        code, out, err = run_cli([export_path])
        assert code == 2
        assert "rbacpath report" in out
        assert "subjects analysed" in out
        assert "can escalate" in err

    def test_subject_filter(self, export_path):
        code, out, err = run_cli(
            [export_path, "--subject", "sa:prod/legacy-job"]
        )
        assert code == 2
        assert "legacy-job" in out
        assert "ci-deployer" not in out

    def test_group_subject(self, export_path):
        code, out, err = run_cli(
            [export_path, "--subject", "group:platform-admins"]
        )
        assert code == 2
        assert "platform-admins" in out

    def test_clean_subject_exits_zero(self, export_path):
        code, out, err = run_cli([export_path, "--subject", "sa:staging/monitor"])
        assert code == 0
        assert "No escalation path found" in out

    def test_bad_subject_is_rejected(self, export_path):
        code, out, err = run_cli([export_path, "--subject", "wizard:merlin"])
        assert code == 1
        assert "unknown subject kind" in err

    def test_json_mode(self, export_path):
        code, out, err = run_cli([export_path, "--format", "json"])
        payload = json.loads(out)
        assert payload["summary"]["privileged"] > 0

    def test_markdown_mode(self, export_path):
        code, out, err = run_cli([export_path, "--format", "markdown"])
        assert out.startswith("## rbacpath report")

    def test_fail_on_critical_only(self, export_path):
        code, out, err = run_cli(
            [export_path, "--subject", "sa:prod/api-sa", "--fail-on", "critical"]
        )
        assert code == 0

    def test_fail_on_none(self, export_path):
        code, out, err = run_cli([export_path, "--fail-on", "none"])
        assert code == 0

    def test_quiet_suppresses_summary(self, export_path):
        code, out, err = run_cli([export_path, "--quiet"])
        assert code == 2
        assert err.strip() == ""

    def test_depth_flag_is_accepted(self, export_path):
        code, out, err = run_cli([export_path, "--depth", "1", "--format", "json"])
        payload = json.loads(out)
        for subject in payload["subjects"]:
            for finding in subject["findings"]:
                assert len(finding["hops"]) == 1 or finding["hops"][0][
                    "primitive"
                ] != "secrets-read"

    def test_stdin_input(self, export_path):
        with open(export_path, "r", encoding="utf-8") as handle:
            text = handle.read()
        code, out, err = run_cli(["-", "--format", "json"], stdin_text=text)
        payload = json.loads(out)
        assert payload["summary"]["subjects"] > 0

    def test_malformed_yaml_reports_cleanly(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("kind: ClusterRole\nmetadata:\n  name: x\nrules: [\n", encoding="utf-8")
        code, out, err = run_cli([str(path)])
        assert code == 1
        assert "rbacpath:" in err


class TestCliJsonFile:
    def test_json_object_input(self, tmp_path, export_path):
        # a single JSON object, not a list, is valid kubectl output too
        path = tmp_path / "one.json"
        payload = {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "root"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "User", "name": "zed"}],
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        code, out, err = run_cli([str(path)])
        # no ClusterRole object present, so the binding cannot be resolved
        assert code == 0
        assert "No escalation path found" in out
