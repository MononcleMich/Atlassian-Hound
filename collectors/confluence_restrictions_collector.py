import logging
from typing import Dict, Iterable

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

from utils.common import PAGE_SIZE, SITE_BASE, get_auth
from utils.environment import link_node_to_environment
from utils.http import get_session
from utils.normalizers import (
    canonical_group_id,
    canonical_page_id,
    canonical_space_id,
    canonical_user_id,
    page_properties,
    group_properties,
    user_properties,
)


LOG = logging.getLogger("AtlassianHound.cfrestrictions")

READ_KEYS = ("read", "view")
WRITE_KEYS = ("update", "edit")


def run(graph) -> None:
    auth = get_auth()
    session = get_session()
    space_nodes = [
        (node_id, node.to_dict())
        for node_id, node in getattr(graph, "nodes", {}).items()
        if "CFSpace" in (node.to_dict().get("kinds") or [])
    ]
    if not space_nodes:
        LOG.warning("No CFSpace nodes present; run spaces collector before restrictions.")
        return
    for space_id, node_data in space_nodes:
        space_props = node_data.get("properties") or {}
        space_key = space_props.get("key")
        if not space_key:
            continue
        LOG.info("Collecting page restrictions for space %s…", space_key)
        _collect_space_pages(graph, session, auth, space_key, space_id)


def _collect_space_pages(graph, session, auth, space_key: str, space_node_id: str) -> None:
    url = f"{SITE_BASE}/wiki/rest/api/content"
    start = 0
    params = {
        "spaceKey": space_key,
        "type": "page",
        "limit": 50,
        "start": start,
        "expand": "restrictions.read.restrictions.user,restrictions.read.restrictions.group,restrictions.update.restrictions.user,restrictions.update.restrictions.group",
    }
    headers = {"Accept": "application/json"}
    while True:
        params["start"] = start
        try:
            resp = session.get(url, auth=auth, headers=headers, params=params)
            resp.raise_for_status()
        except Exception as exc:
            LOG.error("Failed to fetch pages for space %s: %s", space_key, exc)
            break
        data = resp.json()
        for page in data.get("results", []):
            _process_page(graph, page, space_node_id)
        if data.get("size", 0) + start >= data.get("totalSize", 0):
            break
        start += data.get("limit", 50)


def _process_page(graph, page: Dict, space_node_id: str) -> None:
    page_id = str(page.get("id"))
    if not page_id:
        return
    title = page.get("title", "")
    space_key = space_node_id.split(":", 1)[-1] if ":" in space_node_id else ""
    page_node_id = canonical_page_id(page_id)
    graph.add_node(
        Node(
            id=page_node_id,
            kinds=["CFPage"],
            properties=Properties(**page_properties(page_id, title, space_key, page.get("type", ""))),
        )
    )
    link_node_to_environment(graph, page_node_id)
    graph.add_edge(Edge(page_node_id, space_node_id, "PageInSpace", Properties()))

    restrictions = page.get("restrictions", {})
    for key in READ_KEYS:
        _add_restriction_edges(graph, page_node_id, restrictions.get(key, {}), permission="read")
    for key in WRITE_KEYS:
        _add_restriction_edges(graph, page_node_id, restrictions.get(key, {}), permission="update")


def _add_restriction_edges(graph, page_node_id: str, restriction: Dict, permission: str) -> None:
    for user in (restriction.get("restrictions", {}).get("user", {}).get("results", []) or []):
        account_id = user.get("accountId")
        if not account_id:
            continue
        user_id = canonical_user_id(account_id)
        if user_id not in getattr(graph, "nodes", {}):
            graph.add_node(
                Node(
                    id=user_id,
                    kinds=["CFUser"],
                    properties=Properties(**user_properties(account_id, user.get("displayName", account_id), user.get("email", ""), True)),
                )
            )
        link_node_to_environment(graph, user_id)
        graph.add_edge(Edge(user_id, page_node_id, "CFPageRestriction", Properties(permission=permission)))
        if permission == "update":
            graph.add_edge(Edge(user_id, page_node_id, "GenericWrite", Properties(source="page-restriction")))
    for group in (restriction.get("restrictions", {}).get("group", {}).get("results", []) or []):
        gid = group.get("id") or group.get("name")
        if not gid:
            continue
        group_id = canonical_group_id(group.get("id"), group.get("name"))
        if group_id not in getattr(graph, "nodes", {}):
            graph.add_node(
                Node(
                    id=group_id,
                    kinds=["CFGroup"],
                    properties=Properties(**group_properties(group.get("id") or group.get("name") or "", group.get("name") or "")),
                )
            )
        link_node_to_environment(graph, group_id)
        graph.add_edge(Edge(group_id, page_node_id, "CFPageRestriction", Properties(permission=permission)))
