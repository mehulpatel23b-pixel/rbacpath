"""Tests for the RBAC data model and the YAML/JSON loader."""

from __future__ import annotations

import json
from textwrap import dedent

import pytest

from rbacpath.model import Binding, Cluster, Role, Rule, Subject, load_cluster


class TestSubjectParsing:
    def test_user_prefix(self):
        subject = Subject.parse("user:alice")
        assert subject.kind == "user"
        assert subject.name == "alice"
        assert subject.label() == "user:alice"

    def test_group_prefix(self):
        subject = Subject.parse("group:system:masters")
        assert subject.kind == "group"
        assert subject.name == "system:masters"

    def test_service_account_with_namespace(self):
        subject = Subject.parse("sa:prod/api-sa")
        assert subject.kind == "serviceaccount"
        assert subject.namespace == "prod"
        assert subject.name == "api-sa"
        assert subject.label() == "serviceaccount:prod/api-sa"

    def test_service_account_aliases(self):
        for raw in ("serviceaccount:prod/api", "service-account:prod/api"):
            subject = Subject.parse(raw)
            assert subject.kind == "serviceaccount"
            assert subject.namespace == "prod"

    def test_bare_name_defaults_to_user(self):
        subject = Subject.parse("bob")
        assert subject.kind == "user"
        assert subject.name == "bob"

    @pytest.mark.parametrize("raw", ["", "   ", "wtf:alice"])
    def test_invalid_subjects_raise(self, raw):
        with pytest.raises(ValueError):
            Subject.parse(raw)


class TestRule:
    def test_missing_verbs_means_all(self):
        rule = Rule.from_dict({"resources": ["pods"]})
        assert rule.allows_all_verbs()
        assert rule.grants("delete", "pods")

    def test_wildcard_resource(self):
        rule = Rule.from_dict({"verbs": ["*"], "resources": ["*"]})
        assert rule.grants("create", "secrets")
        assert rule.grants("bind", "clusterroles")

    def test_subresource_wildcard_covers_exec(self):
        rule = Rule.from_dict({"verbs": ["create"], "resources": ["pods/*"]})
        assert rule.grants("create", "pods/exec")

    def test_verb_is_case_insensitive(self):
        rule = Rule.from_dict({"verbs": ["GET"], "resources": ["Secrets"]})
        assert rule.grants("get", "secrets")

    def test_resource_names_are_reported(self):
        rule = Rule.from_dict(
            {"verbs": ["get"], "resources": ["secrets"], "resourceNames": ["db"]}
        )
        assert "names: db" in rule.describe()

    def test_non_resource_urls_describe(self):
        rule = Rule.from_dict({"verbs": ["get"], "nonResourceURLs": ["/healthz"]})
        assert "/healthz" in rule.describe()

    def test_does_not_grant_unlisted_verb(self):
        rule = Rule.from_dict({"verbs": ["get"], "resources": ["secrets"]})
        assert not rule.grants("list", "secrets")


class TestLoader:
    def test_loads_all_four_kinds(self, sample_cluster):
        assert len(sample_cluster.roles) == 6
        assert len(sample_cluster.bindings) == 7

    def test_clusterrole_and_role_keep_distinct_keys(self, sample_cluster):
        assert ("ClusterRole", "", "cluster-admin") in sample_cluster.roles
        assert ("Role", "prod", "secret-reader") in sample_cluster.roles

    def test_service_account_subjects_are_normalised(self, sample_cluster):
        subjects = sample_cluster.subjects_of()
        assert Subject("serviceaccount", "ci-deployer", "staging") in subjects
        assert Subject("user", "alice@example.com") in subjects
        assert Subject("group", "platform-admins") in subjects

    def test_role_binding_resolves_to_namespaced_role(self, sample_cluster):
        binding = next(
            b for b in sample_cluster.bindings if b.name == "api-sa-secrets"
        )
        role = sample_cluster.role_for(binding)
        assert role is not None
        assert role.cluster_scoped is False
        assert role.name == "secret-reader"

    def test_json_list_input(self):
        doc = {
            "kind": "List",
            "items": [
                {
                    "kind": "ClusterRole",
                    "metadata": {"name": "admin"},
                    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
                }
            ],
        }
        cluster = load_cluster(json.dumps(doc))
        assert ("ClusterRole", "", "admin") in cluster.roles

    def test_unknown_kinds_are_ignored(self):
        text = dedent(
            """
            kind: ConfigMap
            metadata:
              name: ignore-me
              namespace: prod
            data:
              a: b
            """
        )
        cluster = load_cluster(text)
        assert cluster.roles == {}
        assert cluster.bindings == []

    def test_multiple_documents_are_split(self):
        text = dedent(
            """
            kind: ClusterRole
            metadata:
              name: one
            rules: []
            ---
            kind: ClusterRole
            metadata:
              name: two
            rules: []
            """
        )
        cluster = load_cluster(text)
        assert len(cluster.roles) == 2

    def test_role_without_namespace_is_rejected(self):
        text = dedent(
            """
            kind: Role
            metadata:
              name: broken
            rules: []
            """
        )
        with pytest.raises(ValueError, match="metadata.namespace"):
            load_cluster(text)

    def test_binding_without_roleref_is_rejected(self):
        text = dedent(
            """
            kind: ClusterRoleBinding
            metadata:
              name: broken
            subjects: []
            """
        )
        with pytest.raises(ValueError, match="roleRef.name"):
            load_cluster(text)

    def test_empty_input_is_empty_cluster(self):
        cluster = load_cluster("   ")
        assert isinstance(cluster, Cluster)
        assert cluster.bindings == []

    def test_subject_with_unknown_kind_is_skipped(self):
        text = dedent(
            """
            kind: ClusterRoleBinding
            metadata:
              name: odd
            roleRef:
              kind: ClusterRole
              name: admin
            subjects:
              - kind: Wizard
                name: merlin
              - kind: User
                name: real
            """
        )
        cluster = load_cluster(text)
        assert cluster.bindings[0].subjects == [Subject("user", "real")]

    def test_metadata_labels_are_kept(self):
        text = dedent(
            """
            kind: ClusterRole
            metadata:
              name: labelled
              labels:
                owner: platform
            rules: []
            """
        )
        cluster = load_cluster(text)
        role = cluster.roles[("ClusterRole", "", "labelled")]
        assert role.labels["owner"] == "platform"


class TestBindingMatching:
    def _binding(self, namespace, subjects, cluster_scoped=False):
        return Binding(
            name="b",
            namespace=namespace,
            cluster_scoped=cluster_scoped,
            role_ref_kind="ClusterRole",
            role_ref_name="admin",
            subjects=subjects,
        )

    def test_service_account_matches_within_namespace(self):
        cluster = Cluster()
        cluster.add_role(
            Role(
                name="admin",
                cluster_scoped=True,
                rules=[Rule.from_dict({"verbs": ["*"], "resources": ["*"]})],
            )
        )
        cluster.add_binding(
            self._binding("prod", [Subject("serviceaccount", "sa", "prod")])
        )
        rules = cluster.rules_for_subject(Subject("serviceaccount", "sa", "prod"))
        assert len(rules) == 1

    def test_service_account_in_other_namespace_does_not_match(self):
        cluster = Cluster()
        cluster.add_role(
            Role(
                name="admin",
                cluster_scoped=True,
                rules=[Rule.from_dict({"verbs": ["*"], "resources": ["*"]})],
            )
        )
        cluster.add_binding(
            self._binding("prod", [Subject("serviceaccount", "sa", "prod")])
        )
        rules = cluster.rules_for_subject(Subject("serviceaccount", "sa", "dev"))
        assert rules == []

    def test_group_membership_is_exact_not_prefix(self):
        cluster = Cluster()
        cluster.add_role(
            Role(
                name="admin",
                cluster_scoped=True,
                rules=[Rule.from_dict({"verbs": ["*"], "resources": ["*"]})],
            )
        )
        cluster.add_binding(
            self._binding("", [Subject("group", "system:masters")], cluster_scoped=True)
        )
        assert cluster.rules_for_subject(Subject("group", "system:masters"))
        assert cluster.rules_for_subject(Subject("group", "system:master")) == []

    def test_binding_to_missing_role_is_ignored(self):
        cluster = Cluster()
        cluster.add_binding(
            self._binding("prod", [Subject("user", "alice")])
        )
        assert cluster.rules_for_subject(Subject("user", "alice")) == []


class TestServiceAccountObjects:
    def test_service_account_objects_are_collected(self, sample_cluster):
        accounts = sample_cluster.service_accounts()
        assert Subject("serviceaccount", "api-sa", "prod") in accounts

    def test_service_account_without_namespace_is_ignored(self):
        text = dedent(
            """
            kind: ServiceAccount
            metadata:
              name: orphan
            """
        )
        cluster = load_cluster(text)
        assert cluster.service_account_names == []
