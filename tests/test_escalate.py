"""Tests for the escalation engine: primitive detection, scoping and chaining."""

from __future__ import annotations

from textwrap import dedent

import pytest

from rbacpath.escalate import PRIMITIVES, analyse_all, find_paths
from rbacpath.model import Subject


def cluster_from(*parts: str):
    """Load YAML built from one or more indented string segments."""
    from rbacpath.model import load_cluster

    cleaned = [dedent(p).strip() for p in parts]
    return load_cluster("\n---\n".join(cleaned))


def load(path: str):
    from rbacpath.model import load_cluster

    with open(path, "r", encoding="utf-8") as handle:
        return load_cluster(handle.read())


def finding_ids(result) -> set:
    return {f.terminal for f in result.findings}


def primitive_ids(result) -> set:
    return {hop.primitive for f in result.findings for hop in f.hops}


CLUSTER_ADMIN_ROLE = """
kind: ClusterRole
metadata:
  name: cluster-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""


class TestPrimitiveCatalogue:
    def test_ids_are_unique(self):
        ids = [p.id for p in PRIMITIVES]
        assert len(ids) == len(set(ids))

    def test_every_primitive_has_a_summary_worthy_description(self):
        for primitive in PRIMITIVES:
            assert primitive.note, primitive.id
            assert primitive.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            assert primitive.confidence in {"high", "medium", "low"}
            assert primitive.yields in {"cluster", "namespace", "node"}
            assert primitive.checks


class TestSinglePrimitive:
    def test_cluster_admin_binding_is_critical(self):
        cluster = cluster_from(
            CLUSTER_ADMIN_ROLE
            + """
---
kind: ClusterRoleBinding
metadata:
  name: admins
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: alice
"""
        )
        result = find_paths(cluster, Subject("user", "alice"))
        assert "cluster_admin" in finding_ids(result)
        assert result.is_privileged

    def test_no_binding_means_no_findings(self):
        cluster = cluster_from(CLUSTER_ADMIN_ROLE)
        result = find_paths(cluster, Subject("user", "nobody"))
        assert result.findings == []
        assert result.notes

    def test_read_only_role_is_not_privileged(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: reader
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["pods", "configmaps"]
                verbs: ["get", "list", "watch"]
            ---
            kind: RoleBinding
            metadata:
              name: reader-bind
              namespace: prod
            roleRef:
              kind: Role
              name: reader
            subjects:
              - kind: ServiceAccount
                name: app
                namespace: prod
            """
        )
        result = find_paths(cluster, Subject("serviceaccount", "app", "prod"))
        assert result.findings == []
        assert result.rule_count == 1

    def test_secrets_read_is_namespace_scoped(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: secret-reader
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["secrets"]
                verbs: ["get"]
            ---
            kind: RoleBinding
            metadata:
              name: sr
              namespace: prod
            roleRef:
              kind: Role
              name: secret-reader
            subjects:
              - kind: User
                name: bob
            """
        )
        result = find_paths(cluster, Subject("user", "bob"))
        assert finding_ids(result) == {"namespace_admin"}
        assert result.findings[0].scope == "prod"
        assert "secrets-read" in primitive_ids(result)

    def test_pod_exec_is_detected(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: execer
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["pods/exec"]
                verbs: ["create"]
            ---
            kind: RoleBinding
            metadata:
              name: execer-bind
              namespace: prod
            roleRef:
              kind: Role
              name: execer
            subjects:
              - kind: User
                name: carol
            """
        )
        result = find_paths(cluster, Subject("user", "carol"))
        assert "pod-exec" in primitive_ids(result)

    def test_impersonate_is_cluster_admin(self):
        cluster = cluster_from(
            """
            kind: ClusterRole
            metadata:
              name: impersonator
            rules:
              - apiGroups: [""]
                resources: ["users"]
                verbs: ["impersonate"]
            ---
            kind: ClusterRoleBinding
            metadata:
              name: imp
            roleRef:
              kind: ClusterRole
              name: impersonator
            subjects:
              - kind: User
                name: dave
            """
        )
        result = find_paths(cluster, Subject("user", "dave"))
        assert "cluster_admin" in finding_ids(result)
        assert "impersonate" in primitive_ids(result)

    def test_token_minting_is_detected(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: token-mint
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["serviceaccounts/token"]
                verbs: ["create"]
            ---
            kind: RoleBinding
            metadata:
              name: tm
              namespace: prod
            roleRef:
              kind: Role
              name: token-mint
            subjects:
              - kind: ServiceAccount
                name: ci
                namespace: prod
            """
        )
        result = find_paths(cluster, Subject("serviceaccount", "ci", "prod"))
        assert "sa-token-mint" in primitive_ids(result)

    def test_csr_approval_is_cluster_admin(self):
        cluster = cluster_from(
            """
            kind: ClusterRole
            metadata:
              name: csr-approver
            rules:
              - apiGroups: ["certificates.k8s.io"]
                resources: ["certificatesigningrequests/approval"]
                verbs: ["update"]
            ---
            kind: ClusterRoleBinding
            metadata:
              name: csr
            roleRef:
              kind: ClusterRole
              name: csr-approver
            subjects:
              - kind: User
                name: erin
            """
        )
        result = find_paths(cluster, Subject("user", "erin"))
        assert "cluster_admin" in finding_ids(result)
        assert "csr-approve" in primitive_ids(result)

    def test_rbac_write_in_namespace_is_not_cluster_admin(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: rbac-editor
              namespace: prod
            rules:
              - apiGroups: ["rbac.authorization.k8s.io"]
                resources: ["roles", "rolebindings"]
                verbs: ["create"]
            ---
            kind: RoleBinding
            metadata:
              name: re
              namespace: prod
            roleRef:
              kind: Role
              name: rbac-editor
            subjects:
              - kind: User
                name: frank
            """
        )
        result = find_paths(cluster, Subject("user", "frank"))
        assert finding_ids(result) == {"namespace_admin"}

    def test_node_proxy_is_cluster_level(self):
        cluster = cluster_from(
            """
            kind: ClusterRole
            metadata:
              name: node-proxy
            rules:
              - apiGroups: [""]
                resources: ["nodes/proxy"]
                verbs: ["get"]
            ---
            kind: ClusterRoleBinding
            metadata:
              name: np
            roleRef:
              kind: ClusterRole
              name: node-proxy
            subjects:
              - kind: User
                name: grace
            """
        )
        result = find_paths(cluster, Subject("user", "grace"))
        assert "cluster_admin" in finding_ids(result)
        assert "node-access" in primitive_ids(result)


class TestScoping:
    def test_cluster_wide_grant_satisfies_namespace_scope(self):
        cluster = cluster_from(
            """
            kind: ClusterRole
            metadata:
              name: secret-reader-all
            rules:
              - apiGroups: [""]
                resources: ["secrets"]
                verbs: ["list"]
            ---
            kind: ClusterRoleBinding
            metadata:
              name: all-ns
            roleRef:
              kind: ClusterRole
              name: secret-reader-all
            subjects:
              - kind: User
                name: henry
            """
        )
        result = find_paths(cluster, Subject("user", "henry"))
        assert "secrets-read" in primitive_ids(result)
        assert result.findings[0].scope == ""

    def test_namespaced_grant_does_not_leak_to_cluster(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: only-prod
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["secrets"]
                verbs: ["get"]
            ---
            kind: RoleBinding
            metadata:
              name: only-prod
              namespace: prod
            roleRef:
              kind: Role
              name: only-prod
            subjects:
              - kind: User
                name: ivy
            """
        )
        result = find_paths(cluster, Subject("user", "ivy"))
        assert all(f.scope == "prod" for f in result.findings)
        assert "cluster_admin" not in finding_ids(result)

    def test_rolebinding_can_bind_a_clusterrole(self):
        cluster = cluster_from(
            CLUSTER_ADMIN_ROLE
            + """
---
kind: RoleBinding
metadata:
  name: ns-admin
  namespace: prod
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: app
    namespace: prod
"""
        )
        result = find_paths(cluster, Subject("serviceaccount", "app", "prod"))
        assert "cluster_admin" in finding_ids(result)
        assert all(f.scope == "" for f in result.findings if f.terminal == "cluster_admin")


class TestChaining:
    def test_secrets_then_privileged_service_account(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: secret-reader
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["secrets"]
                verbs: ["get"]
            ---
            kind: RoleBinding
            metadata:
              name: sr
              namespace: prod
            roleRef:
              kind: Role
              name: secret-reader
            subjects:
              - kind: User
                name: jack
            """,
            CLUSTER_ADMIN_ROLE,
            """
            kind: ClusterRoleBinding
            metadata:
              name: app-admin
            roleRef:
              kind: ClusterRole
              name: cluster-admin
            subjects:
              - kind: ServiceAccount
                name: app
                namespace: prod
            """,
        )
        result = find_paths(cluster, Subject("user", "jack"))
        chained = [f for f in result.findings if len(f.hops) > 1]
        assert chained, "expected a two-hop path through a privileged SA"
        assert chained[0].terminal == "cluster_admin"
        assert chained[0].hops[0].primitive == "secrets-read"
        assert chained[0].hops[1].primitive == "sa-token-reuse"
        assert chained[0].confidence == "medium"

    def test_no_chain_when_namespace_has_no_privileged_sa(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: secret-reader
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["secrets"]
                verbs: ["get"]
            ---
            kind: RoleBinding
            metadata:
              name: sr
              namespace: prod
            roleRef:
              kind: Role
              name: secret-reader
            subjects:
              - kind: User
                name: kim
            """
        )
        result = find_paths(cluster, Subject("user", "kim"))
        assert all(len(f.hops) == 1 for f in result.findings)


class TestAnalyseAll:
    def test_analyses_every_subject(self, sample_cluster):
        results = analyse_all(sample_cluster)
        subjects = {r.subject for r in results}
        assert "serviceaccount:prod/legacy-job" in subjects
        assert "serviceaccount:staging/ci-deployer" in subjects
        assert "user:alice@example.com" in subjects

    def test_cluster_admin_subjects_sort_first(self, sample_cluster):
        results = analyse_all(sample_cluster)
        first = results[0]
        assert any(f.terminal == "cluster_admin" for f in first.findings)

    def test_legacy_job_gets_namespace_admin_via_rbac_write(self, sample_cluster):
        """RoleBinding write is namespace takeover, not cluster takeover."""
        result = find_paths(
            sample_cluster, Subject("serviceaccount", "legacy-job", "prod")
        )
        assert finding_ids(result) == {"namespace_admin"}
        assert "rbac-write-ns" in primitive_ids(result)
        assert result.findings[0].scope == "prod"

    def test_ci_deployer_impersonation_is_cluster_admin(self, sample_cluster):
        result = find_paths(
            sample_cluster, Subject("serviceaccount", "ci-deployer", "staging")
        )
        assert "cluster_admin" in finding_ids(result)

    def test_monitor_stays_unprivileged(self, sample_cluster):
        result = find_paths(
            sample_cluster, Subject("serviceaccount", "monitor", "staging")
        )
        assert result.findings == []

    def test_unknown_subject_is_clean(self, sample_cluster):
        result = find_paths(sample_cluster, Subject("user", "ghost"))
        assert result.findings == []
        assert result.rule_count == 0

    def test_depth_zero_stops_chaining(self, sample_cluster):
        result = find_paths(
            sample_cluster, Subject("serviceaccount", "api-sa", "prod"), depth=1
        )
        assert all(len(f.hops) == 1 for f in result.findings)


class TestRuleMetadata:
    def test_resource_names_warning_is_surfaced(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: one-secret
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["secrets"]
                resourceNames: ["db-creds"]
                verbs: ["get"]
            ---
            kind: RoleBinding
            metadata:
              name: os
              namespace: prod
            roleRef:
              kind: Role
              name: one-secret
            subjects:
              - kind: User
                name: lee
            """
        )
        result = find_paths(cluster, Subject("user", "lee"))
        detail = result.findings[0].hops[0].detail
        assert "resource names" in detail.lower()
        assert "db-creds" in detail

    def test_hop_records_role_and_binding_origin(self):
        cluster = cluster_from(
            CLUSTER_ADMIN_ROLE
            + """
---
kind: ClusterRoleBinding
metadata:
  name: admins
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: mo
"""
        )
        result = find_paths(cluster, Subject("user", "mo"))
        hop = result.findings[0].hops[0]
        assert hop.role_ref == "ClusterRole/cluster-admin"
        assert hop.binding_ref == "ClusterRoleBinding/admins"
        assert hop.rule_text


class TestChainedFindingSubject:
    def test_chained_finding_keeps_the_original_subject(self):
        cluster = cluster_from(
            """
            kind: Role
            metadata:
              name: secret-reader
              namespace: prod
            rules:
              - apiGroups: [""]
                resources: ["secrets"]
                verbs: ["list"]
            ---
            kind: RoleBinding
            metadata:
              name: sr
              namespace: prod
            roleRef:
              kind: Role
              name: secret-reader
            subjects:
              - kind: User
                name: nina
            """,
            CLUSTER_ADMIN_ROLE,
            """
            kind: ClusterRoleBinding
            metadata:
              name: ns-admin-sa
            roleRef:
              kind: ClusterRole
              name: cluster-admin
            subjects:
              - kind: ServiceAccount
                name: worker
                namespace: prod
            """,
        )
        result = find_paths(cluster, Subject("user", "nina"))
        chained = [f for f in result.findings if len(f.hops) > 1]
        assert chained
        assert chained[0].subject == "user:nina"


class TestCollapse:
    def test_wildcard_rule_reports_one_finding_per_rule(self, sample_cluster):
        """A * on * rule satisfies many primitives; report the strongest once."""
        result = find_paths(sample_cluster, Subject("user", "alice@example.com"))
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.terminal == "cluster_admin"
        assert finding.hops[0].role_ref == "ClusterRole/cluster-admin"

    def test_distinct_rules_stay_separate(self, sample_cluster):
        result = find_paths(
            sample_cluster, Subject("serviceaccount", "ci-deployer", "staging")
        )
        rules = {f.hops[0].role_ref for f in result.findings}
        assert rules == {"ClusterRole/identity-switcher", "Role/prod/secret-reader"}

    def test_namespace_duplicates_collapse_to_cluster_scope(self, sample_cluster):
        result = find_paths(sample_cluster, Subject("user", "alice@example.com"))
        scopes = {f.scope for f in result.findings}
        assert scopes == {""}
