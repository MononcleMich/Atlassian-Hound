import logging
from typing import Dict, Iterable

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

import requests

from utils.environment import link_node_to_environment
from utils.common import SITE_BASE, get_auth
from utils.http import get_session, handle_http_error
from utils.normalizers import (
    canonical_confluence_permission_id,
    canonical_global_permission_id,
    canonical_instance_node,
    canonical_user_id,
    canonical_group_id,
    global_permission_properties,
    user_properties,
    group_properties,
)


LOG = logging.getLogger("AtlassianHound.global")

JIRA_GLOBAL_PERMISSION_TO_EDGE = {
    "ADMINISTER": "AdminTo",
}

CONFLUENCE_OPERATIONS_TO_EDGE = {
    "administer_space": "AdminTo",
    "edit": "GenericWrite",
    "create": "GenericWrite",
}


def _ensure_instance_nodes(graph) -> Dict[str, str]:
    nodes = {}
    for product in ("Jira", "Confluence"):
        nid = canonical_instance_node(product)
        if nid not in getattr(graph, "nodes", {}):
            graph.add_node(
                Node(
                    id=nid,
                    kinds=[f"{product}Instance"],
                    properties=Properties(name=f"{product} Cloud Instance", objectid=nid),
                )
            )
        link_node_to_environment(graph, nid)
        nodes[product] = nid
    return nodes


def run(graph) -> None:
    auth = get_auth()
    session = get_session()
    LOG.info("Collecting Jira global permissions…")
    instance_nodes = _ensure_instance_nodes(graph)
    _collect_jira_global_permissions(graph, session, auth, instance_nodes["Jira"])
    LOG.info("Collecting Confluence global permissions…")
    _collect_confluence_global_permissions(graph, session, auth, instance_nodes["Confluence"])


def _collect_jira_global_permissions(graph, session, auth, instance_node_id: str) -> None:
    url = f"{SITE_BASE}/rest/api/3/globalpermissions/assignments"
    try:
        resp = session.get(url, auth=auth)
    except requests.RequestException as exc:
        LOG.error("Failed to enumerate Jira global permissions: %s", exc)
        return
    if resp.status_code == 404:
        LOG.info("Jira global permissions endpoint not available for this instance. Skipping.")
        return
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        handle_http_error(resp, "Jira global permissions enumeration")
        return
    data = resp.json()
    assignments: Iterable[Dict] = data.get("globalPermissions", [])
    for entry in assignments:
        perm_key = entry.get("permission")
        if not perm_key:
            continue
        description = entry.get("description", "")
        perm_node_id = canonical_global_permission_id(perm_key)
        graph.add_node(
            Node(
                id=perm_node_id,
                kinds=["JGlobalPermission"],
                properties=Properties(**global_permission_properties(perm_key, description, "Jira")),
            )
        )
        link_node_to_environment(graph, perm_node_id)
        graph.add_edge(
            Edge(
                perm_node_id,
                instance_node_id,
                "AppliesTo",
                Properties(scope="instance"),
            )
        )
        holders = entry.get("holders", {})
        _link_permission_holders(
            graph,
            perm_node_id,
            holders.get("users", []),
            holders.get("groups", []),
            auth,
            session,
        )
        edge_kind = JIRA_GLOBAL_PERMISSION_TO_EDGE.get(perm_key.upper())
        if edge_kind:
            _mirror_permission_edge(graph, perm_node_id, instance_node_id, edge_kind)


def _collect_confluence_global_permissions(graph, session, auth, instance_node_id: str) -> None:
    url = f"{SITE_BASE}/wiki/api/v2/global/permissions"
    next_url = url
    while next_url:
        try:
            resp = session.get(next_url, auth=auth)
        except requests.RequestException as exc:
            LOG.error("Failed to enumerate Confluence global permissions: %s", exc)
            break
        if resp.status_code == 404:
            LOG.info("Confluence global permissions endpoint not available. Skipping.")
            return
        if resp.status_code == 400:
            LOG.info("Confluence global permissions endpoint restricted for this token. Skipping.")
            return
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            handle_http_error(resp, "Confluence global permissions enumeration")
            return
        payload = resp.json()
        for result in payload.get("results", []):
            operation = result.get("operation", {})
            perm_key = operation.get("key")
            if not perm_key:
                continue
            target_type = operation.get("targetType", "")
            perm_node_id = canonical_confluence_permission_id(perm_key)
            graph.add_node(
                Node(
                    id=perm_node_id,
                    kinds=["CFGlobalPermission"],
                    properties=Properties(
                        **global_permission_properties(perm_key, target_type, "Confluence")
                    ),
                )
            )
            link_node_to_environment(graph, perm_node_id)
            graph.add_edge(
                Edge(
                    perm_node_id,
                    instance_node_id,
                    "AppliesTo",
                    Properties(scope="instance"),
                )
            )
            principal = result.get("principal", {})
            _link_confluence_principal(graph, perm_node_id, principal)
            key_lower = perm_key.lower()
            for keyword, edge_kind in CONFLUENCE_OPERATIONS_TO_EDGE.items():
                if keyword in key_lower:
                    _mirror_permission_edge(graph, perm_node_id, instance_node_id, edge_kind)
                    break
        next_link = payload.get("_links", {}).get("next")
        next_url = f"{SITE_BASE}{next_link}" if next_link else None


def _link_permission_holders(graph, perm_node_id: str, users: Iterable[Dict], groups: Iterable[Dict], auth, session) -> None:
    for user in users or []:
        account_id = (user.get("accountId") or "").strip()
        display_name = user.get("displayName") or account_id
        email = user.get("emailAddress", "")
        if not account_id:
            continue
        user_id = canonical_user_id(account_id)
        if user_id not in getattr(graph, "nodes", {}):
            graph.add_node(
                Node(
                    id=user_id,
                    kinds=["CFUser"],
                    properties=Properties(**user_properties(account_id, display_name, email, True)),
                )
            )
        link_node_to_environment(graph, user_id)
        graph.add_edge(Edge(user_id, perm_node_id, "JHasGlobalPermission", Properties()))

    for group in groups or []:
        gid = group.get("groupId") or group.get("name")
        if not gid:
            continue
        group_id = canonical_group_id(group.get("groupId"), group.get("name"))
        if group_id not in getattr(graph, "nodes", {}):
            props = group_properties(group.get("groupId") or group.get("name") or "", group.get("name") or "")
            graph.add_node(Node(id=group_id, kinds=["CFGroup"], properties=Properties(**props)))
        link_node_to_environment(graph, group_id)
        graph.add_edge(Edge(group_id, perm_node_id, "JHasGlobalPermission", Properties()))


def _link_confluence_principal(graph, perm_node_id: str, principal: Dict) -> None:
    p_type = principal.get("type")
    pid = principal.get("id") or principal.get("accountId") or principal.get("externalId")
    if not pid:
        return
    if p_type == "user":
        node_id = canonical_user_id(pid)
        display = principal.get("displayName") or pid
        email = principal.get("email") or ""
        if node_id not in getattr(graph, "nodes", {}):
            graph.add_node(
                Node(
                    id=node_id,
                    kinds=["CFUser"],
                    properties=Properties(**user_properties(pid, display, email, True)),
                )
            )
        link_node_to_environment(graph, node_id)
        graph.add_edge(Edge(node_id, perm_node_id, "CFHasGlobalPermission", Properties()))
    elif p_type == "group":
        node_id = canonical_group_id(principal.get("id"), principal.get("displayName"))
        if node_id not in getattr(graph, "nodes", {}):
            props = group_properties(principal.get("id") or principal.get("displayName") or "", principal.get("displayName") or "")
            graph.add_node(Node(id=node_id, kinds=["CFGroup"], properties=Properties(**props)))
        link_node_to_environment(graph, node_id)
        graph.add_edge(Edge(node_id, perm_node_id, "CFHasGlobalPermission", Properties()))


def _mirror_permission_edge(graph, perm_node_id: str, instance_node_id: str, edge_kind: str) -> None:
    edges = getattr(graph, "edges", [])
    for edge in edges:
        if getattr(edge, "start_node", None) == perm_node_id and edge.kind.startswith("JHasGlobalPermission"):
            graph.add_edge(
                Edge(
                    edge.start_node,
                    instance_node_id,
                    edge_kind,
                    Properties(source="global-permission"),
                )
            )
