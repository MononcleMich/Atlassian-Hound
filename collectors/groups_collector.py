import logging

from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties

from utils.common import get_auth, SITE_BASE, PAGE_SIZE
from utils.environment import link_node_to_environment
from utils.http import get_session
from utils.normalizers import (
    canonical_group_id,
    canonical_user_id,
    group_properties,
    user_properties,
)

LOG = logging.getLogger("AtlassianHound.groups")

def run(graph):
    """
    Collect Jira groups and their members, exporting as OpenGraph nodes/edges.
    Mirrors BloodHound-native membership edges and records membership caches for reuse.
    """
    auth = get_auth()
    session = get_session()
    LOG.info("[OpenGraph] Starting group collection.")

    group_index = getattr(graph, "atlassian_group_index", {"by_id": {}, "by_name": {}})
    graph.atlassian_group_index = group_index
    group_membership = getattr(graph, "group_membership", {})
    graph.group_membership = group_membership

    groups = []
    seen_group_nodes = set()
    seen_user_nodes = set()

    start_at = 0
    page_num = 1
    while True:
        url = f"{SITE_BASE}/rest/api/3/group/bulk"
        params = {"startAt": start_at, "maxResults": PAGE_SIZE}
        try:
            response = session.get(url, auth=auth, params=params)
            response.raise_for_status()
        except Exception as exc:
            LOG.error("Failed to fetch groups: %s", exc)
            break

        payload = response.json()
        values = payload.get("values", [])
        if not values:
            break

        for entry in values:
            raw_group_id = (entry.get("groupId") or "").strip()
            name = (entry.get("name") or "").strip()
            if not raw_group_id and not name:
                continue
            node_id = canonical_group_id(raw_group_id if raw_group_id else None, name if name else None)
            if node_id in seen_group_nodes:
                continue
            group_id_property = raw_group_id or name
            props = group_properties(group_id_property, name or raw_group_id)
            if not props["groupId"] or not props["name"]:
                continue

            graph.add_node(Node(id=node_id, kinds=["CFGroup"], properties=Properties(**props)))
            link_node_to_environment(graph, node_id)
            seen_group_nodes.add(node_id)
            group_membership.setdefault(node_id, set())
            groups.append({"node_id": node_id, "api_id": raw_group_id, "name": name})
            if raw_group_id:
                group_index["by_id"][raw_group_id] = node_id
            if name:
                group_index["by_name"][name.lower()] = node_id

        LOG.info("Fetched %d groups (total: %d) • page %d", len(values), len(seen_group_nodes), page_num)
        if len(values) < PAGE_SIZE:
            break
        start_at += PAGE_SIZE
        page_num += 1

    group_children = {}
    for group in groups:
        start_members = 0
        node_id = group["node_id"]
        members_for_group = group_membership.setdefault(node_id, set())
        while True:
            params = {"startAt": start_members, "maxResults": PAGE_SIZE}
            if group["api_id"]:
                params["groupId"] = group["api_id"]
            else:
                params["groupname"] = group["name"]
            try:
                response = session.get(f"{SITE_BASE}/rest/api/3/group/member", auth=auth, params=params)
                response.raise_for_status()
            except Exception as exc:
                LOG.error("[OpenGraph] Failed to fetch members for group %s: %s", group["name"] or group["api_id"], exc)
                break

            data = response.json()
            members = data.get("values", [])
            if not members:
                break

            for member in members:
                if not member.get("active", False):
                    continue
                if (member.get("displayName") or "").strip().lower() == "former user":
                    continue

                # Nested group membership
                if member.get("groupId") and not member.get("emailAddress"):
                    child_node_id = canonical_group_id(member.get("groupId"), member.get("displayName"))
                    if child_node_id not in seen_group_nodes:
                        child_name = (member.get("displayName") or member.get("groupId") or "").strip()
                        child_props = group_properties(member.get("groupId") or child_name, child_name)
                        if child_props["groupId"] and child_props["name"]:
                            graph.add_node(Node(id=child_node_id, kinds=["CFGroup"], properties=Properties(**child_props)))
                            link_node_to_environment(graph, child_node_id)
                            seen_group_nodes.add(child_node_id)
                            group_membership.setdefault(child_node_id, set())
                            if member.get("groupId"):
                                group_index["by_id"][member["groupId"]] = child_node_id
                            if child_name:
                                group_index["by_name"][child_name.lower()] = child_node_id
                    group_children.setdefault(child_node_id, set()).add(node_id)
                    continue

                account_id = (member.get("accountId") or "").strip()
                display_name = (member.get("displayName") or "").strip()
                email = (member.get("emailAddress") or "").strip()
                if not account_id or not display_name:
                    continue

                user_id = canonical_user_id(account_id)
                if user_id not in seen_user_nodes:
                    user_props = user_properties(account_id, display_name, email, member.get("active", True))
                    graph.add_node(Node(id=user_id, kinds=["CFUser"], properties=Properties(**user_props)))
                    seen_user_nodes.add(user_id)
                    link_node_to_environment(graph, user_id)

                members_for_group.add(user_id)
                for edge_name, reverse_edge in [("CFMemberOfGroup", "CFGroupHasMember"), ("MemberOf", "GroupHasMember")]:
                    graph.add_edge(Edge(user_id, node_id, edge_name, Properties(direct=True)))
                    graph.add_edge(Edge(node_id, user_id, reverse_edge, Properties(direct=True)))

            LOG.info(
                "  Group '%s': added %d members",
                group["name"] or group["api_id"],
                len(members),
            )
            if len(members) < PAGE_SIZE:
                break
            start_members += PAGE_SIZE

    from collections import deque

    ancestors = {group["node_id"]: set() for group in groups}
    for child_node_id, parents in group_children.items():
        ancestors.setdefault(child_node_id, set()).update(parents)
        if child_node_id not in group_membership:
            group_membership[child_node_id] = set()

    for group_id in list(ancestors.keys()):
        queue = deque(ancestors[group_id])
        while queue:
            ancestor = queue.popleft()
            if ancestor in ancestors[group_id]:
                continue
            ancestors[group_id].add(ancestor)
            queue.extend(ancestors.get(ancestor, []))

    for group_id, user_ids in list(group_membership.items()):
        for ancestor in ancestors.get(group_id, []):
            for user_id in user_ids:
                for edge_name, reverse_edge in [("CFMemberOfGroup", "CFGroupHasMember"), ("MemberOf", "GroupHasMember")]:
                    graph.add_edge(Edge(user_id, ancestor, edge_name, Properties(inherited=True)))
                    graph.add_edge(Edge(ancestor, user_id, reverse_edge, Properties(inherited=True)))
            group_membership.setdefault(ancestor, set()).update(user_ids)

    LOG.info("Group collection complete. Total: %d groups with memberships", len(seen_group_nodes))
