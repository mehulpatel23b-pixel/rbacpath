"""Shared fixtures and helpers for the rbacpath test suite."""

from __future__ import annotations

import os
import sys
from textwrap import dedent
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples", "export.yaml")


def rules_to_doc(kind: str, name: str, rules: List[Dict[str, Any]], ns: str = "") -> str:
    """Build a small RBAC object as YAML text."""
    import json as _json

    lines = [f"kind: {kind}", "metadata:", f"  name: {name}"]
    if ns:
        lines.append(f"  namespace: {ns}")
    lines.append("rules:")
    for rule in rules:
        lines.append("  - " + _json.dumps(rule))
    return "\n".join(lines)


@pytest.fixture()
def export_path() -> str:
    return EXAMPLES


@pytest.fixture()
def sample_cluster():
    from rbacpath import load_cluster

    with open(EXAMPLES, "r", encoding="utf-8") as handle:
        return load_cluster(handle.read(), source="export.yaml")


def yaml_cluster(text: str):
    from rbacpath import load_cluster

    return load_cluster(dedent(text).strip())
