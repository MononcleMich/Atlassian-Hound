import logging
from typing import Dict, Iterable

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

from utils.common import ATLASSIAN_API_BASE, ATLASSIAN_ORG_ID, get_auth
from utils.environment import link_node_to_environment
from utils.http import get_session
from utils.normalizers import (
    canonical_group_id,
    canonical_org_role_id,
    canonical_user_id,
    group_properties,
    org_role_properties,
    user_properties,
)


LOG = logging.getLogger("AtlassianHound.orgadmin")


def run(graph) -> None:
    if not ATLASSIAN_ORG_ID:
        LOG.warning("ATLASSIAN_ORG_ID not configured; skipping org admin collector.")
        return
    session = get_session()
    auth = get_auth()
    roles = _fetch_roles(session, auth)
    if not roles:
        LOG.info("No organization roles returned.")
        return
    for role in roles:
        role_id = role.get("id") or role.get("roleId")
        if not role_id:
            continue
        node_id = canonical_org_role_id(role_id)
        graph.add_node(
            Node(
                id=node_id,
                kinds=["OrgRole"],
                properties=Properties(**org_role_properties(role_id, role.get("name", ""), role.get("description", ""))),
            )
        )
        link_node_to_environment(graph, node_id)
        _link_role_members(graph, session, auth, node_id, role_id)


def _fetch_roles(session, auth) -> Iterable[Dict]:
    url = f"{ATLASSIAN_API_BASE}/admin/v1/orgs/{ATLASSIAN_ORG_ID}/roles"
    try:
        resp = session.get(url, auth=auth)
        resp.raise_for_status()
    except Exception as exc:
        LOG.error("Unable to fetch organization roles: %s", exc)
        return []
    return resp.json().get("data", [])


def _link_role_members(graph, session, auth, role_node_id: str, role_id: str) -> None:
    url = f"{ATLASSIAN_API_BASE}/admin/v1/orgs/{ATLASSIAN_ORG_ID}/users"
    params = {"role-id": role_id}
    try:
        resp = session.get(url, auth=auth, params=params)
        resp.raise_for_status()
    except Exception as exc:
        LOG.error("Failed to enumerate members for org role %s: %s", role_id, exc)
        return
    for entry in resp.json().get("data", []):
        principal_type = entry.get("type")
        if principal_type == "user":
            account_id = entry.get("id")
            if not account_id:
                continue
            user_id = canonical_user_id(account_id)
            if user_id not in getattr(graph, "nodes", {}):
                graph.add_node(
                    Node(
                        id=user_id,
                        kinds=["CFUser"],
                        properties=Properties(**user_properties(account_id, entry.get("displayName", account_id), entry.get("email", ""), True)),
                    )
                )
            link_node_to_environment(graph, user_id)
            graph.add_edge(Edge(user_id, role_node_id, "AssignedOrgRole", Properties()))
        elif principal_type == "group":
            group_id = canonical_group_id(entry.get("id"), entry.get("displayName"))
            if group_id not in getattr(graph, "nodes", {}):
                graph.add_node(
                    Node(
                        id=group_id,
                        kinds=["CFGroup"],
                        properties=Properties(**group_properties(entry.get("id") or entry.get("displayName") or "", entry.get("displayName") or "")),
                    )
                )
            link_node_to_environment(graph, group_id)
            graph.add_edge(Edge(group_id, role_node_id, "AssignedOrgRole", Properties()))
