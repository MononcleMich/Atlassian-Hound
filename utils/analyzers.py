from __future__ import annotations

import re
from collections import Counter
from typing import Dict, Iterable, Set

from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties


ADMIN_KEYWORDS = ("administer", "system_admin", "admin", "manage")
WRITE_KEYWORDS = ("edit", "write", "modify", "maintain", "update", "createissue", "create_issue")
SERVICE_ACCOUNT_PATTERNS = ("svc", "service", "automation", "bot", "cicd")


def apply_privilege_analytics(graph) -> None:
    """
    Enrich the in-memory graph with derived privilege edges and high-value markings.
    - Promotes Jira role permissions to canonical AdminTo / GenericWrite edges.
    - Marks principals with administrative access as high-value for BloodHound triage.
    - Adds risk scoring and service-account hints.
    """
    nodes = getattr(graph, "nodes", {})
    edges = getattr(graph, "edges", [])
    if not nodes or not edges:
        return

    permission_labels: Dict[str, str] = {}
    for node_id, node in nodes.items():
        node_data = node.to_dict() if hasattr(node, "to_dict") else {}
        kinds = set(node_data.get("kinds") or [])
        if kinds & {"JPermission", "JGlobalPermission", "CFGlobalPermission"}:
            props = node_data.get("properties") or {}
            label = (props.get("permission") or "").lower()
            permission_labels[node_id] = label

    role_to_project: Dict[str, Set[str]] = {}
    role_permissions: Dict[str, Set[str]] = {}
    role_user_members: Dict[str, Set[str]] = {}
    role_group_members: Dict[str, Set[str]] = {}
    existing_admin_edges: Set[tuple[str, str]] = set()
    admin_principals: Set[str] = set()
    generic_write_principals: Set[str] = set()

    for edge in list(edges):
        kind = getattr(edge, "kind", "")
        start = getattr(edge, "start_node", None)
        end = getattr(edge, "end_node", None)
        if not start or not end:
            continue
        if kind == "JRoleInProject":
            role_to_project.setdefault(start, set()).add(end)
        elif kind == "JRoleHasPermission":
            role_permissions.setdefault(start, set()).add(end)
        elif kind == "JAssignedToRole":
            role_user_members.setdefault(end, set()).add(start)
        elif kind == "JGroupAssignedToRole":
            role_group_members.setdefault(end, set()).add(start)
        elif kind == "AdminTo":
            existing_admin_edges.add((start, end))
            admin_principals.add(start)
        elif kind == "GenericWrite":
            generic_write_principals.add(start)
        elif kind == "JHasGlobalPermission":
            label = permission_labels.get(end, "")
            if "administer" in label or "admin" in label:
                admin_principals.add(start)
        elif kind == "AssignedOrgRole":
            admin_principals.add(start)
        elif kind == "CFHasGlobalPermission":
            label = permission_labels.get(end, "")
            if "admin" in label:
                admin_principals.add(start)
        elif kind == "JServiceDeskAgent":
            admin_principals.add(start)

    group_membership: Dict[str, Set[str]] = getattr(graph, "group_membership", {})

    for role_id, permission_ids in role_permissions.items():
        projects = role_to_project.get(role_id, set())
        if not projects:
            continue
        labels = [permission_labels.get(pid, "") for pid in permission_ids]
        lower_labels = [label for label in labels if label]

        grants_admin = any(any(keyword in label for keyword in ADMIN_KEYWORDS) for label in lower_labels)
        grants_write = any(any(keyword in label for keyword in WRITE_KEYWORDS) for label in lower_labels)

        if not grants_admin and not grants_write:
            continue

        direct_users = role_user_members.get(role_id, set())
        group_ids = role_group_members.get(role_id, set())
        inherited_users: Set[str] = set()
        for group_id in group_ids:
            inherited_users.update(group_membership.get(group_id, set()))

        if grants_admin:
            _emit_edges(graph, direct_users, projects, "AdminTo", inherit=False, existing=existing_admin_edges)
            _emit_edges(graph, inherited_users, projects, "AdminTo", inherit=True, existing=existing_admin_edges)
            admin_principals.update(direct_users | inherited_users)

        if grants_write:
            _emit_edges(graph, direct_users, projects, "GenericWrite", inherit=False)
            _emit_edges(graph, inherited_users, projects, "GenericWrite", inherit=True)
            generic_write_principals.update(direct_users | inherited_users)

    _mark_high_value(nodes, admin_principals | generic_write_principals)
    _apply_service_account_flags(nodes)
    _apply_risk_scores(graph)


def _emit_edges(
    graph,
    principals: Iterable[str],
    targets: Iterable[str],
    kind: str,
    inherit: bool,
    existing: Set[tuple[str, str]] | None = None,
) -> None:
    graph_nodes = getattr(graph, "nodes", {})
    for principal in principals:
        if principal not in graph_nodes:
            continue
        for target in targets:
            if target not in graph_nodes:
                continue
            if existing and kind == "AdminTo" and (principal, target) in existing:
                continue
            props = {"source": "analyzer"}
            if inherit:
                props["inherited"] = "true"  # Store as string for Properties compatibility
            graph.add_edge(Edge(principal, target, kind, Properties(**props)))
            if existing is not None and kind == "AdminTo":
                existing.add((principal, target))


def _mark_high_value(nodes: Dict[str, object], principal_ids: Iterable[str]) -> None:
    for principal_id in principal_ids:
        node = nodes.get(principal_id)
        if not node:
            continue
        setattr(node, "high_value", True)
        _set_node_property(node, "high_value", True)


def _classify_risk_level(risk_score: int) -> str:
    """
    Classify risk level based on privilege edge count.
    """
    if risk_score >= 10:
        return "CRITICAL"
    elif risk_score >= 5:
        return "HIGH"
    elif risk_score >= 2:
        return "MEDIUM"
    elif risk_score >= 1:
        return "LOW"
    return "NONE"


def _apply_risk_scores(graph) -> None:
    edges: Iterable[Edge] = getattr(graph, "edges", [])
    nodes = getattr(graph, "nodes", {})
    counter: Counter[str] = Counter()
    for edge in edges:
        if edge.kind in ("AdminTo", "GenericWrite"):
            start = getattr(edge, "start_node", None)
            if start:
                counter[start] += 1
    for node_id, score in counter.items():
        node = nodes.get(node_id)
        if not node:
            continue
        setattr(node, "risk_score", score)
        _set_node_property(node, "risk_score", score)
        # Add risk level classification for BloodHound filtering
        risk_level = _classify_risk_level(score)
        setattr(node, "risk_level", risk_level)
        _set_node_property(node, "risk_level", risk_level)


def _apply_service_account_flags(nodes: Dict[str, object]) -> None:
    for node in nodes.values():
        node_dict = node.to_dict() if hasattr(node, "to_dict") else {}  # type: ignore[union-attr]
        kinds = set(node_dict.get("kinds") or [])
        if not (kinds & {"CFUser", "User"}):
            continue
        props = node_dict.get("properties") or {}
        name = str(props.get("displayName") or props.get("name") or node_dict.get("label") or "").lower()
        email = str(props.get("emailAddress") or props.get("email") or "").lower()
        is_service = (
            any(pattern in name for pattern in SERVICE_ACCOUNT_PATTERNS)
            or (email and email.startswith(("svc", "service", "automation")))
            or (not email and name)
        )
        if is_service:
            setattr(node, "service_account", True)
            _set_node_property(node, "service_account", True)


def _set_node_property(node, key: str, value) -> None:
    if hasattr(node, "set_property"):
        node.set_property(key, value)
    elif hasattr(node, "properties"):
        try:
            node.properties[key] = value  # type: ignore[attr-defined]
        except Exception:
            pass
