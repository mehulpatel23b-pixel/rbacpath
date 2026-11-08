"""Escalation analysis: turn RBAC rules into concrete privilege-escalation paths.

The analyser answers one question: *given these rules, what can this subject
actually end up controlling, and which single rule unlocks each step?*

Every escalation technique is expressed as a :class:`Primitive`, which is a
data record: the permissions it needs, the scope it needs them in, and what it
yields. That keeps the engine small and makes the rule set auditable, which
matters for a security tool people will read before trusting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .model import Binding, Cluster, Role, Rule, Subject

CLUSTER_SCOPE = ""

_READ = {"get", "list", "watch"}
_WRITE = {"create", "update", "patch", "delete", "deletecollection"}
_RBAC_WRITE = {"create", "update", "patch", "bind", "escalate", "delete"}


@dataclass(frozen=True)
class Primitive:
    """One escalation technique.

    ``checks`` is a list of (verbs, resources) groups. The primitive applies
    when a single rule grants any verb in ``verbs`` on any resource in
    ``resources`` at a matching scope.
    """

    id: str
    title: str
    severity: str
    confidence: str
    yields: str  # "cluster" | "namespace" | "node"
    checks: Tuple[Tuple[Set[str], Set[str]], ...]
    note: str = ""
    cluster_only: bool = False


PRIMITIVES: Tuple[Primitive, ...] = (
    Primitive(
        id="rbac-write-ns",
        title="Can rewrite RBAC in a namespace",
        severity="HIGH",
        confidence="high",
        yields="namespace",
        checks=((_RBAC_WRITE, {"roles", "rolebindings"}),),
        note=(
            "Writing Roles or RoleBindings allows granting any permission inside "
            "this namespace, including reading its secrets."
        ),
    ),
    Primitive(
        id="rbac-write-cluster",
        title="Can rewrite cluster-scoped RBAC",
        severity="CRITICAL",
        confidence="high",
        yields="cluster",
        checks=((_RBAC_WRITE, {"clusterroles", "clusterrolebindings"}),),
        cluster_only=True,
        note=(
            "ClusterRole/ClusterRoleBinding write is cluster-admin: bind "
            "cluster-admin to yourself and the cluster is yours."
        ),
    ),
    Primitive(
        id="bind-escalate",
        title="Holds bind or escalate on a privileged role",
        severity="CRITICAL",
        confidence="high",
        yields="cluster",
        checks=(({"bind", "escalate"}, {"roles", "clusterroles"}),),
        note=(
            "The bind and escalate verbs exist precisely to hand out permissions "
            "the caller does not hold. On a ClusterRole this is full takeover."
        ),
    ),
    Primitive(
        id="impersonate",
        title="Can impersonate users, groups or service accounts",
        severity="CRITICAL",
        confidence="high",
        yields="cluster",
        checks=(
            (
                {"impersonate"},
                {"users", "groups", "serviceaccounts", "uids", "userextras"},
            ),
        ),
        note=(
            "Impersonation inherits every permission of the target identity. "
            "Impersonating system:masters or an admin user is cluster-admin."
        ),
    ),
    Primitive(
        id="secrets-read",
        title="Can read Secrets in a namespace",
        severity="HIGH",
        confidence="medium",
        yields="namespace",
        checks=((_READ, {"secrets"}),),
        note=(
            "Secrets hold service account tokens, cloud credentials and API keys. "
            "Reading them is credential theft, not just information disclosure."
        ),
    ),
    Primitive(
        id="pod-create",
        title="Can create workloads",
        severity="HIGH",
        confidence="high",
        yields="namespace",
        checks=(
            (_WRITE, {"pods", "deployments", "daemonsets", "statefulsets",
                      "replicasets", "jobs", "cronjobs"}),
        ),
        note=(
            "Creating a workload lets an attacker mount any ServiceAccount token "
            "in the namespace, and a privileged pod with hostPath or hostPID "
            "reaches the node itself."
        ),
    ),
    Primitive(
        id="pod-exec",
        title="Can exec into or attach to pods",
        severity="HIGH",
        confidence="high",
        yields="namespace",
        checks=(({"create", "get"}, {"pods/exec", "pods/attach"}),),
        note=(
            "Exec inherits the target pod's ServiceAccount and filesystem, which "
            "is usually a straight path to its token and mounted secrets."
        ),
    ),
    Primitive(
        id="sa-token-mint",
        title="Can mint ServiceAccount tokens",
        severity="HIGH",
        confidence="high",
        yields="namespace",
        checks=(({"create"}, {"serviceaccounts/token"}),),
        note=(
            "TokenRequest on serviceaccounts/token issues a valid bearer token "
            "for any ServiceAccount in the namespace."
        ),
    ),
    Primitive(
        id="csr-approve",
        title="Can approve or sign CertificateSigningRequests",
        severity="CRITICAL",
        confidence="high",
        yields="cluster",
        checks=(
            (
                {"approve", "sign", "update", "patch"},
                {"certificatesigningrequests/approval",
                 "certificatesigningrequests/status",
                 "certificatesigningrequests"},
            ),
        ),
        note=(
            "Approving your own CSR with a signer you control yields a client "
            "certificate for any identity, including system:masters."
        ),
    ),
    Primitive(
        id="node-access",
        title="Can reach the kubelet or node API",
        severity="CRITICAL",
        confidence="high",
        yields="cluster",
        checks=(
            (
                {"get", "create", "update", "patch", "delete"},
                {"nodes/proxy", "nodes/exec", "nodes"},
            ),
        ),
        note=(
            "The kubelet API accepts pod specs and serves logs and exec without "
            "API server authorisation, so node-level access is cluster-level."
        ),
    ),
    Primitive(
        id="admission-webhook",
        title="Can write admission webhook configuration",
        severity="CRITICAL",
        confidence="high",
        yields="cluster",
        checks=(
            (
                _WRITE,
                {"mutatingwebhookconfigurations", "validatingwebhookconfigurations"},
            ),
        ),
        note=(
            "A mutating webhook sees and rewrites every pod that is created, "
            "which is a persistence and credential-theft primitive cluster-wide."
        ),
    ),
    Primitive(
        id="persistent-volume",
        title="Can create PersistentVolumes",
        severity="HIGH",
        confidence="medium",
        yields="node",
        checks=(({"create", "update", "patch"}, {"persistentvolumes"}),),
        note=(
            "A hostPath PersistentVolume plus a claiming pod reads the node "
            "filesystem, including kubelet credentials and other pods' tokens."
        ),
    ),
)


@dataclass
class Hop:
    """One step of a path, tied to the rule that enables it."""

    primitive: str
    title: str
    detail: str
    scope: str
    role_ref: str
    binding_ref: str
    rule_text: str
    confidence: str
    severity: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "primitive": self.primitive,
            "title": self.title,
            "detail": self.detail,
            "scope": self.scope or "cluster-wide",
            "role": self.role_ref,
            "binding": self.binding_ref,
            "rule": self.rule_text,
            "confidence": self.confidence,
            "severity": self.severity,
        }


@dataclass
class Finding:
    """A reachable outcome for a subject, with the hops that get there."""

    subject: str
    terminal: str  # cluster_admin | namespace_admin | node_escape
    scope: str
    severity: str
    confidence: str
    hops: List[Hop] = field(default_factory=list)
    summary: str = ""

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    def to_dict(self) -> Dict[str, object]:
        return {
            "subject": self.subject,
            "terminal": self.terminal,
            "scope": self.scope or "cluster-wide",
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "hops": [h.to_dict() for h in self.hops],
        }


@dataclass
class PathResult:
    """Everything the analyser concluded about one subject."""

    subject: str
    findings: List[Finding] = field(default_factory=list)
    rule_count: int = 0
    notes: List[str] = field(default_factory=list)

    @property
    def is_privileged(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> Dict[str, object]:
        return {
            "subject": self.subject,
            "rule_count": self.rule_count,
            "notes": list(self.notes),
            "findings": [f.to_dict() for f in self.findings],
        }


# ------------------------------------------------------------------ internals


def _scope_matches(grant_scope: str, query_scope: str) -> bool:
    """A cluster-wide grant satisfies a namespace query; the reverse never does."""
    if grant_scope == CLUSTER_SCOPE:
        return True
    return grant_scope == query_scope


def _grants(
    rules: Sequence[Tuple[Rule, Binding, Role, str]],
    verb: str,
    resource: str,
    scope: str,
) -> Optional[Tuple[Rule, Binding, Role, str]]:
    for rule, binding, role, rule_scope in rules:
        if not _scope_matches(rule_scope, scope):
            continue
        if rule.grants(verb, resource):
            return (rule, binding, role, rule_scope)
    return None


def _rule_text(rule: Rule) -> str:
    return rule.describe()


def _hop_from(
    primitive: Primitive,
    match: Tuple[Rule, Binding, Role, str],
    scope: str,
    detail_extra: str = "",
) -> Hop:
    rule, binding, role, rule_scope = match
    detail = primitive.note
    if detail_extra:
        detail = f"{detail} {detail_extra}".strip()
    if rule.resource_names:
        detail += (
            f" Note: this rule is limited to resource names "
            f"({', '.join(rule.resource_names)}), so the path must target one of them."
        )
    return Hop(
        primitive=primitive.id,
        title=primitive.title,
        detail=detail,
        scope=scope,
        role_ref=role.describe_ref(),
        binding_ref=binding.describe_ref(),
        rule_text=_rule_text(rule),
        confidence=primitive.confidence,
        severity=primitive.severity,
    )


def _candidate_scopes(cluster: Cluster, subject: Subject) -> List[str]:
    scopes = {CLUSTER_SCOPE}
    for binding in cluster.bindings:
        if binding.namespace:
            scopes.add(binding.namespace)
    for rule, _binding, _role, rule_scope in cluster.rules_for_subject(subject):
        if rule_scope:
            scopes.add(rule_scope)
    if subject.namespace:
        scopes.add(subject.namespace)
    return sorted(scopes)


def _privileged_namespace_service_accounts(
    cluster: Cluster, namespace: str, depth: int, visited: Set[Tuple[str, str, str]]
) -> List[Tuple[Subject, Finding]]:
    """Service accounts in a namespace that reach cluster-admin themselves.

    Used to turn a plain ``read secrets`` finding into the two-step path real
    attackers use: steal a token out of a namespace, then borrow its identity.
    """
    out: List[Tuple[Subject, Finding]] = []
    if depth <= 0:
        return out
    for account in cluster.service_accounts():
        if account.namespace != namespace:
            continue
        if account.key in visited:
            continue
        result = _analyse(cluster, account, depth - 1, visited | {account.key})
        for finding in result.findings:
            if finding.terminal == "cluster_admin":
                out.append((account, finding))
                break
    return out


def _analyse(
    cluster: Cluster,
    subject: Subject,
    depth: int = 2,
    visited: Optional[Set[Tuple[str, str, str]]] = None,
) -> PathResult:
    visited = visited or {subject.key}
    rules = cluster.rules_for_subject(subject)
    result = PathResult(subject=subject.label(), rule_count=len(rules))

    if not rules:
        result.notes.append(
            "No Role or ClusterRole is bound to this subject, so it holds no "
            "policy-derived permissions."
        )
        return result

    findings: List[Finding] = []
    seen_key: Set[Tuple[str, str]] = set()

    for scope in _candidate_scopes(cluster, subject):
        for primitive in PRIMITIVES:
            if primitive.cluster_only and scope != CLUSTER_SCOPE:
                continue
            for verbs, resources in primitive.checks:
                match = None
                for verb in sorted(verbs):
                    for resource in sorted(resources):
                        match = _grants(rules, verb, resource, scope)
                        if match:
                            break
                    if match:
                        break
                if not match:
                    continue

                if primitive.yields == "cluster":
                    terminal, out_scope = "cluster_admin", CLUSTER_SCOPE
                elif primitive.yields == "namespace":
                    terminal, out_scope = "namespace_admin", scope
                    if scope == CLUSTER_SCOPE:
                        # a namespace primitive on a cluster-wide rule gives
                        # every namespace, but not cluster-admin by itself
                        out_scope = CLUSTER_SCOPE
                else:
                    terminal, out_scope = "node_escape", scope

                key = (primitive.id, out_scope)
                if key in seen_key:
                    continue

                hop = _hop_from(primitive, match, out_scope)
                finding = Finding(
                    subject=subject.label(),
                    terminal=terminal,
                    scope=out_scope,
                    severity=primitive.severity,
                    confidence=primitive.confidence,
                    hops=[hop],
                )
                finding.summary = _summarise(primitive)

                if primitive.id == "secrets-read" and depth > 0:
                    chained = _chained_secret_path(
                        cluster, scope, hop, depth, visited, subject.label()
                    )
                    if chained is not None:
                        findings.append(chained)
                        seen_key.add(("secrets-read-chained", scope))
                        seen_key.add(key)
                        continue

                seen_key.add(key)
                findings.append(finding)

    result.findings = _collapse(findings)
    return result


_TERMINAL_RANK = {"cluster_admin": 0, "node_escape": 1, "namespace_admin": 2}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _collapse(findings: List[Finding]) -> List[Finding]:
    """One finding per enabling rule, keeping the strongest outcome.

    A wildcard cluster-admin rule technically satisfies most primitives at once
    (and every namespace primitive twice, once per scope). Reporting all of them
    buries the one line that matters, so findings that trace back to the same
    rule are collapsed to the highest-impact terminal.
    """
    best: Dict[Tuple[object, ...], Finding] = {}
    for finding in findings:
        if len(finding.hops) > 1:
            key: Tuple[object, ...] = ("chained", finding.hops[0].binding_ref,
                                       finding.hops[0].rule_text)
        else:
            hop = finding.hops[0]
            key = ("single", hop.role_ref, hop.binding_ref, hop.rule_text)
        score = (
            _TERMINAL_RANK.get(finding.terminal, 9),
            _SEVERITY_RANK.get(finding.severity, 9),
            finding.scope,
        )
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        current_score = (
            _TERMINAL_RANK.get(current.terminal, 9),
            _SEVERITY_RANK.get(current.severity, 9),
            current.scope,
        )
        if score < current_score:
            best[key] = finding

    collapsed = list(best.values())
    collapsed.sort(
        key=lambda f: (
            _TERMINAL_RANK.get(f.terminal, 9),
            _SEVERITY_RANK.get(f.severity, 9),
            f.scope,
            f.summary,
        )
    )
    return collapsed


def _summarise(primitive: Primitive) -> str:
    return {
        "rbac-write-ns": "Can grant itself any permission in this namespace.",
        "rbac-write-cluster": "Can grant itself cluster-admin.",
        "bind-escalate": "Can attach an existing privileged role to itself.",
        "impersonate": "Can act as a more privileged identity.",
        "secrets-read": "Can read credentials stored in this namespace.",
        "pod-create": "Can run code with any ServiceAccount in this namespace.",
        "pod-exec": "Can run commands inside an existing pod.",
        "sa-token-mint": "Can issue a token for any ServiceAccount here.",
        "csr-approve": "Can certify itself as any identity, including system:masters.",
        "node-access": "Can reach the kubelet API directly.",
        "admission-webhook": "Can intercept and rewrite every pod created cluster-wide.",
        "persistent-volume": "Can read the node filesystem through a hostPath volume.",
    }.get(primitive.id, primitive.title)


def _chained_secret_path(
    cluster: Cluster,
    scope: str,
    first_hop: Hop,
    depth: int,
    visited: Set[Tuple[str, str, str]],
    subject_label: str,
) -> Optional[Finding]:
    """Build the secrets -> privileged ServiceAccount -> cluster path."""
    namespace = scope or None
    if not namespace:
        return None
    accounts = _privileged_namespace_service_accounts(
        cluster, namespace, depth, visited
    )
    if not accounts:
        return None
    account, downstream = accounts[0]
    second = Hop(
        primitive="sa-token-reuse",
        title=f"Use the stolen token of {account.label()}",
        detail=(
            f"{account.label()} in {namespace} reaches cluster-admin on its own. "
            "A token read from a Secret in this namespace inherits those rights."
        ),
        scope=CLUSTER_SCOPE,
        role_ref=downstream.hops[0].role_ref if downstream.hops else "-",
        binding_ref=downstream.hops[0].binding_ref if downstream.hops else "-",
        rule_text="(inherited via stolen service account token)",
        confidence="medium",
        severity="CRITICAL",
    )
    return Finding(
        subject=subject_label,
        terminal="cluster_admin",
        scope=CLUSTER_SCOPE,
        severity="CRITICAL",
        confidence="medium",
        hops=[first_hop, second] + downstream.hops,
        summary=(
            f"Read Secrets in {namespace}, reuse the privileged ServiceAccount "
            "token found there, then follow its own path to cluster-admin."
        ),
    )


def find_paths(
    cluster: Cluster,
    subject: Subject,
    depth: int = 2,
) -> PathResult:
    """Analyse one subject. ``depth`` bounds service-account chaining."""
    return _analyse(cluster, subject, depth=max(1, depth))


def analyse_all(cluster: Cluster, depth: int = 2) -> List[PathResult]:
    """Analyse every subject that appears in a binding, highest severity first."""
    subjects = sorted(cluster.subjects_of(), key=lambda s: (s.kind, s.name))
    results = [find_paths(cluster, subject, depth=depth) for subject in subjects]
    order = {"cluster_admin": 0, "node_escape": 1, "namespace_admin": 2}
    results.sort(
        key=lambda r: (
            min((order.get(f.terminal, 9) for f in r.findings), default=9),
            r.subject,
        )
    )
    return results
