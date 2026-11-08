"""Data model for Kubernetes RBAC objects plus a loader for exported YAML.

Only the fields that matter for escalation analysis are kept. Everything is
normalised so the rest of the package never has to think about the difference
between a Role and a ClusterRole, or between YAML and dict input.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# Verbs that mean "all verbs". Also used when a rule omits `verbs`.
_WILDCARD = "*"

# Resources that, when writable, are effectively equivalent to full control of
# a workload and therefore a route to the node / service account token.
WORKLOAD_RESOURCES = {
    "pods",
    "pods/exec",
    "pods/attach",
    "pods/portforward",
    "deployments",
    "daemonsets",
    "statefulsets",
    "replicasets",
    "jobs",
    "cronjobs",
}

# Resources whose read access leaks credentials or cluster state.
SECRET_RESOURCES = {"secrets"}


def _as_list(value: Any) -> List[str]:
    """Coerce a scalar, list or None into a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


@dataclass(frozen=True)
class Subject:
    """An RBAC subject: user, group or serviceaccount."""

    kind: str
    name: str
    namespace: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _norm_kind(self.kind))

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.kind, self.namespace or "", self.name)

    def label(self) -> str:
        if self.kind == "serviceaccount" and self.namespace:
            return f"serviceaccount:{self.namespace}/{self.name}"
        return f"{self.kind}:{self.name}"

    @classmethod
    def parse(cls, raw: str) -> "Subject":
        """Parse ``user:alice``, ``group:system:masters`` or ``sa:ns/name``."""
        text = (raw or "").strip()
        if not text:
            raise ValueError("empty subject")
        if ":" not in text:
            return cls(kind="user", name=text)
        kind, rest = text.split(":", 1)
        kind = kind.strip().lower()
        rest = rest.strip()
        if kind in {"sa", "serviceaccount", "service-account"}:
            if "/" in rest:
                ns, name = rest.split("/", 1)
                return cls(kind="serviceaccount", name=name, namespace=ns)
            return cls(kind="serviceaccount", name=rest)
        if kind in {"u", "user"}:
            return cls(kind="user", name=rest)
        if kind in {"g", "group"}:
            return cls(kind="group", name=rest)
        raise ValueError(f"unknown subject kind {kind!r} in {raw!r}")


def _norm_kind(kind: str) -> str:
    k = (kind or "").strip().lower()
    mapping = {
        "user": "user",
        "u": "user",
        "group": "group",
        "g": "group",
        "serviceaccount": "serviceaccount",
        "service-account": "serviceaccount",
        "sa": "serviceaccount",
    }
    if k not in mapping:
        raise ValueError(f"unknown subject kind {kind!r}")
    return mapping[k]


@dataclass(frozen=True)
class Rule:
    """A single policy rule, normalised."""

    verbs: Tuple[str, ...] = ()
    resources: Tuple[str, ...] = ()
    api_groups: Tuple[str, ...] = ()
    resource_names: Tuple[str, ...] = ()
    non_resource_urls: Tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Rule":
        verbs = tuple(_as_list(raw.get("verbs")) or [_WILDCARD])
        return cls(
            verbs=tuple(v.lower() for v in verbs),
            resources=tuple(_as_list(raw.get("resources"))),
            api_groups=tuple(_as_list(raw.get("apiGroups"))),
            resource_names=tuple(_as_list(raw.get("resourceNames"))),
            non_resource_urls=tuple(_as_list(raw.get("nonResourceURLs"))),
        )

    def allows_verb(self, verb: str) -> bool:
        verb = verb.lower()
        return _WILDCARD in self.verbs or verb in self.verbs

    def allows_all_verbs(self) -> bool:
        return _WILDCARD in self.verbs

    def allows_resource(self, resource: str) -> bool:
        res = resource.lower()
        if _WILDCARD in self.resources:
            return True
        if res in (r.lower() for r in self.resources):
            return True
        # "pods/exec" style rules: a rule granting pods/* covers subresources
        if "/" in res:
            head = res.split("/", 1)[0]
            if f"{head}/*" in self.resources:
                return True
        return False

    def grants(self, verb: str, resource: str) -> bool:
        return self.allows_verb(verb) and self.allows_resource(resource)

    def describe(self) -> str:
        verbs = ",".join(self.verbs) or "*"
        res = ",".join(self.resources) or ",".join(self.non_resource_urls) or "-"
        text = f"{verbs} on {res}"
        if self.resource_names:
            text += f" (names: {', '.join(self.resource_names)})"
        return text


@dataclass
class Role:
    """A Role or ClusterRole. ``cluster_scoped`` distinguishes the two."""

    name: str
    namespace: Optional[str] = None
    cluster_scoped: bool = False
    rules: List[Rule] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> Tuple[str, str, str]:
        kind = "ClusterRole" if self.cluster_scoped else "Role"
        return (kind, self.namespace or "", self.name)

    @property
    def kind(self) -> str:
        return "ClusterRole" if self.cluster_scoped else "Role"

    def describe_ref(self) -> str:
        if self.cluster_scoped:
            return f"ClusterRole/{self.name}"
        return f"Role/{self.namespace}/{self.name}"


@dataclass
class Binding:
    """A RoleBinding or ClusterRoleBinding."""

    name: str
    namespace: Optional[str] = None
    cluster_scoped: bool = False
    role_ref_kind: str = "Role"
    role_ref_name: str = ""
    subjects: List[Subject] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)

    @property
    def kind(self) -> str:
        return "ClusterRoleBinding" if self.cluster_scoped else "RoleBinding"

    def describe_ref(self) -> str:
        if self.cluster_scoped:
            return f"ClusterRoleBinding/{self.name}"
        return f"RoleBinding/{self.namespace}/{self.name}"

    def role_key(self) -> Tuple[str, str, str]:
        """Key of the Role/ClusterRole this binding points at."""
        kind = (self.role_ref_kind or "").strip().lower()
        if kind == "clusterrole":
            return ("ClusterRole", "", self.role_ref_name)
        # A RoleBinding may bind a ClusterRole; the grant is namespaced but the
        # rules come from the ClusterRole object.
        if kind == "role":
            return ("Role", self.namespace or "", self.role_ref_name)
        return ("ClusterRole", "", self.role_ref_name)


@dataclass
class Cluster:
    """An exported slice of cluster RBAC plus lookups used by the analyser."""

    roles: Dict[Tuple[str, str, str], Role] = field(default_factory=dict)
    bindings: List[Binding] = field(default_factory=list)
    pod_specs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    service_account_names: List[Subject] = field(default_factory=list)
    source: str = "inline"

    # ---------------------------------------------------------------- helpers
    def add_role(self, role: Role) -> None:
        self.roles[role.key] = role

    def add_binding(self, binding: Binding) -> None:
        self.bindings.append(binding)

    def role_for(self, binding: Binding) -> Optional[Role]:
        return self.roles.get(binding.role_key())

    def rules_for_subject(
        self, subject: Subject
    ) -> List[Tuple[Rule, Binding, Role, str]]:
        """Every rule that applies to a subject, with its origin and scope.

        Returns tuples of (rule, binding, role, scope_namespace). An empty
        scope_namespace means cluster-wide.
        """
        out: List[Tuple[Rule, Binding, Role, str]] = []
        for binding in self.bindings:
            if not _binding_matches(binding, subject):
                continue
            role = self.role_for(binding)
            if role is None:
                continue
            scope = "" if binding.cluster_scoped else (binding.namespace or "")
            for rule in role.rules:
                out.append((rule, binding, role, scope))
        return out

    def subjects_of(self) -> Set[Subject]:
        seen: Set[Subject] = set()
        for binding in self.bindings:
            for subject in binding.subjects:
                seen.add(subject)
        return seen

    def service_accounts(self) -> Set[Subject]:
        out: Set[Subject] = set()
        for binding in self.bindings:
            for subject in binding.subjects:
                if subject.kind == "serviceaccount":
                    out.add(subject)
        for ns, spec in self.pod_specs.items():
            name = (spec or {}).get("serviceAccountName")
            if name:
                out.add(Subject(kind="serviceaccount", name=name, namespace=ns))
        out.update(self.service_account_names)
        return out


def _binding_matches(binding: Binding, subject: Subject) -> bool:
    """True when a binding grants to the subject, directly or via group."""
    for candidate in binding.subjects:
        if candidate.kind != subject.kind:
            continue
        if candidate.name != subject.name:
            continue
        if subject.kind == "serviceaccount":
            # A subject may name its namespace; a namespaced binding may instead
            # supply it implicitly. Both must agree when both are present.
            if candidate.namespace and candidate.namespace != subject.namespace:
                continue
            if (
                not candidate.namespace
                and not binding.cluster_scoped
                and binding.namespace
                and binding.namespace != subject.namespace
            ):
                continue
        return True
    return False


# --------------------------------------------------------------------- loading


def _iter_documents(payload: str) -> Iterable[Dict[str, Any]]:
    """Parse a multi-document YAML or JSON listing of RBAC objects."""
    text = payload.strip()
    if not text:
        return []
    if text.startswith("{") or text.startswith("["):
        data = json.loads(text)
        if isinstance(data, dict):
            items = data.get("items")
            if isinstance(items, list):
                return [i for i in items if isinstance(i, dict)]
            return [data]
        return [i for i in data if isinstance(i, dict)]
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only without pyyaml
        raise RuntimeError(
            "YAML input needs PyYAML. Install it with 'pip install rbacpath[yaml]' "
            "or export the objects as JSON with 'kubectl get ... -o json'."
        ) from exc
    docs = []
    for doc in yaml.safe_load_all(text):
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            docs.extend(i for i in doc["items"] if isinstance(i, dict))
        else:
            docs.append(doc)
    return docs


def _meta(doc: Dict[str, Any]) -> Tuple[str, Optional[str], Dict[str, str]]:
    meta = doc.get("metadata") or {}
    name = str(meta.get("name") or "").strip()
    namespace = meta.get("namespace")
    labels = {str(k): str(v) for k, v in (meta.get("labels") or {}).items()}
    return name, (str(namespace) if namespace else None), labels


def _role_from_doc(doc: Dict[str, Any]) -> Role:
    kind = str(doc.get("kind") or "").strip().lower()
    name, namespace, labels = _meta(doc)
    if not name:
        raise ValueError(f"{kind or 'object'} is missing metadata.name")
    cluster_scoped = kind == "clusterrole"
    if not cluster_scoped and not namespace:
        raise ValueError(f"Role/{name} is missing metadata.namespace")
    rules = [Rule.from_dict(r) for r in (doc.get("rules") or []) if isinstance(r, dict)]
    return Role(
        name=name,
        namespace=None if cluster_scoped else namespace,
        cluster_scoped=cluster_scoped,
        rules=rules,
        labels=labels,
    )


def _subject_from_raw(raw: Dict[str, Any]) -> Optional[Subject]:
    kind = raw.get("kind")
    name = raw.get("name")
    if not kind or not name:
        return None
    namespace = raw.get("namespace")
    try:
        return Subject(
            kind=str(kind),
            name=str(name),
            namespace=(str(namespace) if namespace else None),
        )
    except ValueError:
        return None


def _binding_from_doc(doc: Dict[str, Any]) -> Binding:
    kind = str(doc.get("kind") or "").strip().lower()
    name, namespace, labels = _meta(doc)
    if not name:
        raise ValueError(f"{kind or 'object'} is missing metadata.name")
    cluster_scoped = kind == "clusterrolebinding"
    if not cluster_scoped and not namespace:
        raise ValueError(f"RoleBinding/{name} is missing metadata.namespace")
    ref = doc.get("roleRef") or {}
    role_ref_kind = str(ref.get("kind") or "Role")
    role_ref_name = str(ref.get("name") or "")
    if not role_ref_name:
        raise ValueError(f"{kind}/{name} has no roleRef.name")
    subjects = []
    for raw in doc.get("subjects") or []:
        if isinstance(raw, dict):
            subject = _subject_from_raw(raw)
            if subject is not None:
                subjects.append(subject)
    return Binding(
        name=name,
        namespace=None if cluster_scoped else namespace,
        cluster_scoped=cluster_scoped,
        role_ref_kind=role_ref_kind,
        role_ref_name=role_ref_name,
        subjects=subjects,
        labels=labels,
    )


def load_cluster(payload: str, source: str = "inline") -> Cluster:
    """Load RBAC objects from YAML/JSON text into a :class:`Cluster`."""
    cluster = Cluster(source=source)
    for doc in _iter_documents(payload):
        kind = str(doc.get("kind") or "").strip().lower()
        if kind in {"role", "clusterrole"}:
            cluster.add_role(_role_from_doc(doc))
        elif kind in {"rolebinding", "clusterrolebinding"}:
            cluster.add_binding(_binding_from_doc(doc))
        elif kind == "serviceaccount":
            name, namespace, _ = _meta(doc)
            if name and namespace:
                cluster.service_account_names.append(
                    Subject(kind="serviceaccount", name=name, namespace=namespace)
                )
        # Other kinds are ignored on purpose: this tool is RBAC-only.
    return cluster
