import logging

from requests import exceptions as requests_exceptions

from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties

from utils.common import get_auth, SITE_BASE, PAGE_SIZE
from utils.environment import link_node_to_environment
from utils.http import get_session
from utils.normalizers import (
    canonical_group_id,
    canonical_permission_id,
    canonical_project_id,
    canonical_role_id,
    canonical_user_id,
    group_properties,
    permission_properties,
    project_properties,
    role_properties,
    user_properties,
)

LOG = logging.getLogger("AtlassianHound.permissions")
SESSION = get_session()

def fetch_user_details(account_id, site_base, auth):
    """Enrich user nodes with displayName and email from Confluence endpoint."""
    try:
        url = f"{site_base}/wiki/rest/api/user?accountId={account_id}"
        r = SESSION.get(url, auth=auth)
        if r.status_code == 401:
            LOG.warning(f"401 Unauthorized when fetching user {account_id}, skipping enrichment.")
            return None, None
        r.raise_for_status()
        data = r.json()
        return data.get("displayName", ""), data.get("email", "")
    except Exception as e:
        LOG.warning(f"Failed to enrich user {account_id}: {e}")
        return None, None

def fetch_permission_scheme(project_id, site_base, auth):
    """Fetch permission scheme for a project and its permissions."""
    try:
        perm_url = f"{site_base}/rest/api/2/project/{project_id}/permissionscheme"
        r = SESSION.get(perm_url, auth=auth)
        if r.status_code == 401:
            LOG.warning(f"401 Unauthorized when fetching permission scheme for project {project_id}, skipping permissions.")
            return None
        r.raise_for_status()
        perm_data = r.json()
        perm_scheme_id = perm_data.get("id")
        if not perm_scheme_id:
            return None

        scheme_url = f"{site_base}/rest/api/2/permissionscheme/{perm_scheme_id}"
        sr = SESSION.get(scheme_url, auth=auth)
        if sr.status_code == 401:
            LOG.warning(f"401 Unauthorized when fetching permission scheme details for project {project_id}, skipping permissions.")
            return None
        sr.raise_for_status()
        scheme_data = sr.json()
        return scheme_data
    except Exception as e:
        LOG.warning(f"Failed to fetch project permissions: {e}")
        return None


def _group_index(graph):
    return getattr(graph, "atlassian_group_index", {"by_id": {}, "by_name": {}})


def _resolve_group_node(graph, identifier):
    if not identifier:
        return None
    index = _group_index(graph)
    by_id = index.get("by_id", {})
    by_name = index.get("by_name", {})
    node_id = by_id.get(identifier)
    if node_id:
        return node_id
    lowered = identifier.lower() if hasattr(identifier, "lower") else None
    if lowered:
        node_id = by_name.get(lowered)
        if node_id:
            return node_id
    node_id = canonical_group_id(identifier, identifier)
    placeholder_tracker = getattr(graph, "_placeholder_groups", set())
    if node_id not in placeholder_tracker:
        props = group_properties(identifier, identifier)
        graph.add_node(Node(id=node_id, kinds=["CFGroup"], properties=Properties(**props)))
        link_node_to_environment(graph, node_id)
        placeholder_tracker.add(node_id)
        graph._placeholder_groups = placeholder_tracker
    if lowered:
        by_name[lowered] = node_id
    if identifier:
        by_id[identifier] = node_id
    index["by_name"] = by_name
    index["by_id"] = by_id
    graph.atlassian_group_index = index
    return node_id


def _lookup_group_members(graph, identifier):
    membership = getattr(graph, "group_membership", {})
    index = _group_index(graph)
    by_id = index.get("by_id", {})
    by_name = index.get("by_name", {})
    node_id = by_id.get(identifier)
    if not node_id and hasattr(identifier, "lower"):
        node_id = by_name.get(identifier.lower())
    if not node_id:
        node_id = canonical_group_id(identifier, identifier)
    return membership.get(node_id, set())

def run(graph):
    """
    Collect project roles and permission schemes, enrich users, and add permission assignments as OpenGraph nodes/edges.
    Node/edge kinds and properties strictly match model.json.
    """
    auth = get_auth()
    LOG.info("Starting permissions collection.")

    seen_role_ids = set()
    seen_user_ids = set()
    seen_group_ids = set()
    seen_perm_ids = set()
    total_401s = 0
    max_401s = 10
    # Get all projects
    url = f"{SITE_BASE}/rest/api/2/project/search"
    params = {"startAt": 0, "maxResults": PAGE_SIZE}
    projects = []
    while url:
        try:
            r = SESSION.get(url, auth=auth, params=params if '?' not in url else None)
            r.raise_for_status()
        except Exception as e:
            LOG.error("Failed to fetch projects for permissions: %s", e)
            break
        d = r.json()
        vals = d.get("values", [])
        if not vals:
            break
        projects.extend(vals)
        url = d.get("nextPage")
        params = None

    for p in projects:
        pid = str(p["id"])
        pnode_id = canonical_project_id(pid)
        graph.add_node(Node(
            id=pnode_id,
            kinds=["JProject"],
            properties=Properties(**project_properties(pid, p.get("key", ""), p.get("name", ""), p.get("projectTypeKey", "")))
        ))
        link_node_to_environment(graph, pnode_id)

        # Get project details (roles etc.)
        proj_url = f"{SITE_BASE}/rest/api/2/project/{pid}"
        try:
            rp = SESSION.get(proj_url, auth=auth)
            rp.raise_for_status()
        except Exception as e:
            LOG.error("Failed to fetch project details for project %s: %s", pid, e)
            continue
        proj_data = rp.json()
        roles = proj_data.get("roles", {})

        for role_name, role_url in roles.items():
            role_identifier = role_url.rstrip('/').split('/')[-1]
            rnode_id = canonical_role_id(pid, role_identifier or role_name, is_numeric=role_identifier.isdigit() if role_identifier else False)
            if rnode_id not in seen_role_ids:
                graph.add_node(Node(
                    id=rnode_id,
                    kinds=["JRole"],
                    properties=Properties(**role_properties(pid, role_identifier or role_name, role_name))
                ))
                seen_role_ids.add(rnode_id)
            link_node_to_environment(graph, rnode_id)
            graph.add_edge(Edge(
                rnode_id,
                pnode_id,
                "JRoleInProject",
                Properties()
            ))

            # Fetch members of the role
            try:
                rr = SESSION.get(role_url, auth=auth)
                rr.raise_for_status()
            except requests_exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 401:
                    total_401s += 1
                    LOG.error(
                        "Failed to fetch role members for project %s role %s: 401 Unauthorized (%d total)",
                        pid, role_name, total_401s
                    )
                    if total_401s >= max_401s:
                        LOG.critical(
                            "Detected %d total 401 Unauthorized errors fetching role members. "
                            "You are likely running with insufficient rights. "
                            "Please re-run AtlassianHound with an administrator user's API key.",
                            total_401s
                        )
                        return  # Stop the collector
                    continue  # Skip this role, don't retry
                else:
                    LOG.error("Failed to fetch role members for project %s role %s: %s", pid, role_name, e)
                    continue
            except Exception as e:
                LOG.error("Failed to fetch role members for project %s role %s: %s", pid, role_name, e)
                continue

            role_data = rr.json()

            # Users in role
            for actor in role_data.get("actors", []):
                if actor.get("type") == "atlassian-user-role-actor" and "accountId" in actor:
                    account_id = actor["accountId"]
                    uid = canonical_user_id(account_id)
                    if uid not in seen_user_ids:
                        display_name, email = fetch_user_details(account_id, SITE_BASE, auth)
                        props = user_properties(
                            account_id=(account_id or "").strip(),
                            display_name=(display_name or actor.get("displayName", "") or "").strip() or account_id,
                            email=(email or "").strip(),
                            active=actor.get("active", True),
                        )
                        if props["accountId"] and props["displayName"]:
                            graph.add_node(Node(id=uid, kinds=["CFUser"], properties=Properties(**props)))
                            seen_user_ids.add(uid)
                    link_node_to_environment(graph, uid)
                    graph.add_edge(Edge(
                        uid,
                        rnode_id,
                        "JAssignedToRole",
                        Properties()
                    ))
                elif actor.get("type") == "atlassian-group-role-actor" and "displayName" in actor:
                    gid = _resolve_group_node(graph, actor["displayName"])
                    if not gid:
                        continue
                    link_node_to_environment(graph, gid)
                    seen_group_ids.add(gid)
                    graph.add_edge(Edge(
                        gid,
                        rnode_id,
                        "JGroupAssignedToRole",
                        Properties()
                    ))

        # Permissions enrichment
        perm_scheme = fetch_permission_scheme(pid, SITE_BASE, auth)
        if perm_scheme and "permissions" in perm_scheme:
            for perm in perm_scheme["permissions"]:
                perm_raw = perm.get("permission")
                if not perm_raw:
                    continue
                perm_label = str(perm_raw)
                perm_key = perm_label.lower()
                perm_id = canonical_permission_id(perm_key)
                if perm_id not in seen_perm_ids:
                    graph.add_node(Node(
                        id=perm_id,
                        kinds=["JPermission"],
                        properties=Properties(**permission_properties(perm_key, perm.get("description") or ""))
                    ))
                    seen_perm_ids.add(perm_id)
                link_node_to_environment(graph, perm_id)
                holder = perm.get("holder", {})
                holder_type = holder.get("type")
                holder_param = holder.get("parameter", "")
                # Edges: who/what holds the permission
                if holder_type == "user":
                    uid = canonical_user_id(holder_param)
                    if uid not in seen_user_ids:
                        display_name, email = fetch_user_details(holder_param, SITE_BASE, auth)
                        props = user_properties(
                            account_id=(holder_param or "").strip(),
                            display_name=(display_name or "").strip() or holder_param,
                            email=(email or "").strip(),
                            active=True,
                        )
                        if props["accountId"] and props["displayName"]:
                            graph.add_node(Node(id=uid, kinds=["CFUser"], properties=Properties(**props)))
                            seen_user_ids.add(uid)
                    link_node_to_environment(graph, uid)
                    graph.add_edge(Edge(
                        uid,
                        perm_id,
                        "JHasPermission",
                        Properties(permission=perm_key)
                    ))
                elif holder_type == "group":
                    gid = _resolve_group_node(graph, holder_param)
                    if not gid:
                        continue
                    link_node_to_environment(graph, gid)
                    seen_group_ids.add(gid)
                    graph.add_edge(Edge(
                        gid,
                        perm_id,
                        "JHasPermission",
                        Properties(permission=perm_key)
                    ))
                elif holder_type == "projectRole":
                    rid = canonical_role_id(pid, str(holder_param), is_numeric=str(holder_param).isdigit())
                    graph.add_edge(Edge(
                        rid,
                        perm_id,
                        "JRoleHasPermission",
                        Properties(permission=perm_key)
                    ))
                # Add more holder types as needed (e.g., applicationRole, authenticated, etc.)

    LOG.info("Permissions collection complete.")
