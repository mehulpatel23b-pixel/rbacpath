"""rbacpath - offline Kubernetes RBAC privilege-escalation path finder.

Reads exported RBAC (Role/ClusterRole + bindings) and reports every
escalation path from a given subject to cluster-admin level access,
with the exact rule that enables each hop.
"""

__version__ = "1.0.0"

from .model import (  # noqa: F401
    Subject,
    Rule,
    Role,
    Binding,
    Cluster,
    load_cluster,
)
from .escalate import (  # noqa: F401
    PRIMITIVES,
    Finding,
    find_paths,
    PathResult,
)
from .report import render_text, render_json, render_markdown  # noqa: F401
