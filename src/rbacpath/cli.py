"""Command line entry point for rbacpath."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .escalate import analyse_all, find_paths
from .model import Cluster, load_cluster
from .report import exit_code, render_json, render_markdown, render_text

EXAMPLES = """examples:
  rbacpath cluster.yaml
  rbacpath cluster.yaml --subject sa:prod/api-sa
  rbacpath cluster.yaml --subject group:system:authenticated --format json
  kubectl get role,rolebinding,clusterrole,clusterrolebinding -A -o yaml | rbacpath -
  rbacpath cluster.yaml --fail-on critical --format markdown > rbac.md
"""

USER_GUIDE = """rbacpath finds privilege-escalation paths in exported Kubernetes RBAC.

It reads Roles, ClusterRoles, RoleBindings and ClusterRoleBindings only. It does
not talk to your cluster, needs no credentials, and makes no network calls.

subject syntax:
  user:alice                  a user
  group:system:masters        a group
  sa:prod/api-sa              a service account (namespace/name)
  sa:api-sa                   a service account, namespace inferred from bindings

exit codes:
  0  no findings (or findings below the --fail-on threshold)
  2  findings at or above the --fail-on threshold
  1  input error
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbacpath",
        description="Offline Kubernetes RBAC privilege-escalation path finder.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="YAML or JSON file with RBAC objects, or '-' to read stdin",
    )
    parser.add_argument(
        "--subject",
        action="append",
        default=None,
        metavar="KIND:NAME",
        help="analyse only this subject (repeatable, e.g. sa:prod/api-sa)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="analyse every subject found in a binding (default when no --subject)",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="how many service-account chaining steps to follow (default: 2)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["any", "critical", "none"],
        default="any",
        help="severity threshold for a non-zero exit code (default: any)",
    )
    parser.add_argument(
        "--max-paths",
        type=int,
        default=3,
        help="maximum findings printed per subject in text mode (default: 3)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the summary line on stderr",
    )
    parser.add_argument(
        "--version", action="version", version=f"rbacpath {__version__}"
    )
    return parser


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _parse_subject(raw: str):
    from .model import Subject

    return Subject.parse(raw)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.input:
        parser.print_help()
        print(USER_GUIDE, file=sys.stderr)
        return 1

    try:
        payload = _read_input(args.input)
    except OSError as exc:
        print(f"rbacpath: cannot read {args.input}: {exc}", file=sys.stderr)
        return 1

    try:
        cluster: Cluster = load_cluster(payload, source=args.input)
    except (ValueError, RuntimeError) as exc:
        print(f"rbacpath: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # malformed YAML from a pipe
        print(f"rbacpath: could not parse input: {exc}", file=sys.stderr)
        return 1

    if not cluster.roles and not cluster.bindings:
        print(
            "rbacpath: input contains no Role, ClusterRole, RoleBinding or "
            "ClusterRoleBinding objects.",
            file=sys.stderr,
        )
        return 1

    if args.subject:
        results = []
        for raw in args.subject:
            try:
                subject = _parse_subject(raw)
            except ValueError as exc:
                print(f"rbacpath: {exc}", file=sys.stderr)
                return 1
            results.append(find_paths(cluster, subject, depth=args.depth))
    else:
        results = analyse_all(cluster, depth=args.depth)

    if args.format == "json":
        print(render_json(results))
    elif args.format == "markdown":
        print(render_markdown(results))
    else:
        print(render_text(results, max_paths=args.max_paths))

    privileged = sum(1 for r in results if r.findings)
    if not args.quiet:
        print(
            f"rbacpath: {privileged} of {len(results)} subjects can escalate",
            file=sys.stderr,
        )

    return exit_code(results, fail_on=args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
