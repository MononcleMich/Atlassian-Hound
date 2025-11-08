import logging
from typing import Dict, Iterable

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

from utils.common import SITE_BASE, get_auth
from utils.environment import link_node_to_environment
from utils.http import get_session
from utils.normalizers import (
    application_role_properties,
    canonical_application_role_id,
    canonical_group_id,
    canonical_instance_node,
    group_properties,
)


LOG = logging.getLogger("AtlassianHound.approles")


def run(graph) -> None:
    auth = get_auth()
    session = get_session()
    url = f"{SITE_BASE}/rest/api/3/applicationrole"
    try:
        resp = session.get(url, auth=auth)
        resp.raise_for_status()
    except Exception as exc:
        LOG.error("Failed to fetch Jira application roles: %s", exc)
        return
    instance_node = canonical_instance_node("Jira")
    if instance_node not in getattr(graph, "nodes", {}):
        graph.add_node(Node(id=instance_node, kinds=["JiraInstance"], properties=Properties(name="Jira Cloud Instance", objectid=instance_node)))
    link_node_to_environment(graph, instance_node)
    for role in resp.json():
        role_key = role.get("key")
        if not role_key:
            continue
        role_id = canonical_application_role_id(role_key)
        default_groups = [g.get("name") or g.get("groupId") for g in role.get("defaultGroups", []) if g]
        props = application_role_properties(
            role_key,
            role.get("name", role_key),
            default_groups,
            role.get("selectedByDefault", False),
        )
        graph.add_node(Node(id=role_id, kinds=["JApplicationRole"], properties=Properties(**props)))
        link_node_to_environment(graph, role_id)
        graph.add_edge(Edge(role_id, instance_node, "AppliesTo", Properties(scope="application")))
        _link_groups(graph, role_id, role.get("groups", []))
        _link_default_groups(graph, role_id, role.get("defaultGroups", []))


def _link_groups(graph, role_node_id: str, groups: Iterable[Dict]) -> None:
    for group in groups or []:
        name = group.get("name") or group.get("groupId")
        if not name:
            continue
        group_id = canonical_group_id(group.get("groupId"), group.get("name"))
        if group_id not in getattr(graph, "nodes", {}):
            props = group_properties(group.get("groupId") or group.get("name") or "", group.get("name") or "")
            graph.add_node(Node(id=group_id, kinds=["CFGroup"], properties=Properties(**props)))
        link_node_to_environment(graph, group_id)
        graph.add_edge(Edge(group_id, role_node_id, "HasProductAccess", Properties(source="application-role")))


def _link_default_groups(graph, role_node_id: str, groups: Iterable[Dict]) -> None:
    for group in groups or []:
        name = group.get("name") or group.get("groupId")
        if not name:
            continue
        group_id = canonical_group_id(group.get("groupId"), group.get("name"))
        if group_id not in getattr(graph, "nodes", {}):
            props = group_properties(group.get("groupId") or group.get("name") or "", group.get("name") or "")
            graph.add_node(Node(id=group_id, kinds=["CFGroup"], properties=Properties(**props)))
        link_node_to_environment(graph, group_id)
        graph.add_edge(Edge(group_id, role_node_id, "HasDefaultAccess", Properties(source="application-role")))
