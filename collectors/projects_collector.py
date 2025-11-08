import logging
import os
from typing import Optional, Tuple

import requests

from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
from collectors.issues_collector import run as collect_issues
from utils.common import get_auth, SITE_BASE, PAGE_SIZE
from utils.environment import link_node_to_environment
from utils.http import get_session
from utils.normalizers import (
    canonical_group_id,
    canonical_issue_id,
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

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("AtlassianHound.projects")

SESSION = get_session()

def fetch_user_details(account_id, site_base, auth):
    """Fetch displayName and email for a user from Confluence endpoint."""
    try:
        url = f"{site_base}/wiki/rest/api/user?accountId={account_id}"
        r = SESSION.get(url, auth=auth, timeout=10)
        if r.status_code == 401:
            LOG.warning(f"401 Unauthorized when fetching user {account_id}, skipping enrichment.")
            return None, None
        r.raise_for_status()
        data = r.json()
        return data.get("displayName"), data.get("email")
    except Exception as e:
        LOG.warning(f"Failed to enrich user {account_id}: {e}")
        return None, None

def fetch_group_details(group_name, site_base, auth):
    """Fetch group details from Confluence endpoint."""
    # Atlassian groups don't have much detail, but you can at least list the name.
    return group_name

def fetch_role_members(role_url, auth):
    """Fetch the users/groups assigned to a Jira project role."""
    try:
        r = SESSION.get(role_url, auth=auth, timeout=15)
        if r.status_code in (401, 403):
            _maybe_log_permission_notice(
                f"Skipping role membership fetch (HTTP {r.status_code}); Atlassian blocks this endpoint for the current API key."
            )
            return [], []
        r.raise_for_status()
        data = r.json()
        users = data.get("actors", [])
        user_ids = [u.get("actorUser", {}).get("accountId") for u in users if u.get("type") == "atlassian-user-role-actor" and u.get("actorUser", {}).get("accountId")]
        group_names = [u.get("displayName") for u in users if u.get("type") == "atlassian-group-role-actor" and u.get("displayName")]
        return user_ids, group_names
    except Exception as e:
        LOG.warning(f"Failed to fetch role members: {e}")
        return [], []

_permission_notice_emitted: bool = False

def _maybe_log_permission_notice(message: str) -> None:
    global _permission_notice_emitted
    if _permission_notice_emitted:
        return
    LOG.info(message)
    _permission_notice_emitted = True

def fetch_project_permissions(project_id, site_base, auth):
    """Fetch permissions for the project."""
    try:
        # 1. Find the permission scheme for the project
        perm_url = f"{site_base}/rest/api/3/project/{project_id}/permissionscheme"
        r = SESSION.get(perm_url, auth=auth, timeout=15)
        if r.status_code in (401, 403):
            # Return None to indicate auth failure (empty list means no permissions)
            return None
        r.raise_for_status()
        perm_data = r.json()
        perm_scheme_id = perm_data.get("id")
        if not perm_scheme_id:
            return []
        # 2. Get the scheme's details
        scheme_url = f"{site_base}/rest/api/3/permissionscheme/{perm_scheme_id}"
        sr = SESSION.get(scheme_url, auth=auth, timeout=15)
        if sr.status_code in (401, 403):
            LOG.info(
                "Skipping permission scheme details for project %s (HTTP %s). Atlassian restricts this endpoint for the current API key; collector continues without detailed permissions.",
                project_id,
                sr.status_code,
            )
            return []
        sr.raise_for_status()
        scheme_data = sr.json()
        return scheme_data.get("permissions", [])
    except requests.HTTPError as exc:
        status = getattr(exc.response, "status_code", None)
        if status in (401, 403):
            LOG.info(
                "Project %s permission scheme inaccessible (HTTP %s); Atlassian is blocking this call for the current API key, so the collector skips it.",
                project_id,
                status,
            )
            return []
        LOG.warning(f"Failed to fetch project permissions: {exc}")
        return []
    except Exception as e:
        LOG.warning(f"Failed to fetch project permissions: {e}")
        return []


def _group_index(graph):
    index = getattr(graph, "atlassian_group_index", {"by_id": {}, "by_name": {}})
    return index


def _resolve_group_node(graph, identifier):
    if not identifier:
        return None
    index = _group_index(graph)
    by_id = index.get("by_id", {})
    by_name = index.get("by_name", {})
    node_id = by_id.get(identifier)
    if node_id:
        return node_id
    if hasattr(identifier, "lower"):
        node_id = by_name.get(identifier.lower())
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
    if hasattr(identifier, "lower"):
        by_name[identifier.lower()] = node_id
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
    Collect Jira projects and their relationships, exporting as OpenGraph nodes/edges.
    Node/edge kinds and properties strictly match model.json.
    Handles pagination and 401 gracefully.
    """
    site_base = os.environ.get("ATLASSIAN_SITE_BASE")
    email = os.environ.get("ATLASSIAN_EMAIL")
    api_token = os.environ.get("ATLASSIAN_API_TOKEN")

    if not site_base or not email or not api_token:
        LOG.critical("Missing environment variables.")
        return

    auth = (email, api_token)
    projects_url = f"{site_base}/rest/api/3/project/search"
    start_at = 0
    max_results = 50
    page_num = 1

    seen_project_ids = set()
    seen_user_ids = set()
    seen_group_names = set()

    # Track skipped operations for summary logging
    skipped_permission_schemes = 0
    skipped_role_collections = 0
    skipped_issues = 0

    while True:
        params = {"startAt": start_at, "maxResults": max_results}
        try:
            r = SESSION.get(projects_url, auth=auth, params=params, timeout=30)
            if r.status_code == 401:
                LOG.warning("401 Unauthorized when fetching projects, stopping collector.")
                break
            r.raise_for_status()
        except Exception as e:
            LOG.error("Failed to fetch projects: %s", e)
            break

        data = r.json()
        projects = data.get("values", [])
        if not projects:
            LOG.info("No projects found.")
            break


        for p in projects:
            pid = canonical_project_id(str(p["id"]))
            if pid in seen_project_ids:
                continue
            seen_project_ids.add(pid)

            # Project node with all required properties
            graph.add_node(Node(
                id=pid,
                kinds=["JProject"],
                properties=Properties(**project_properties(str(p.get("id", "")), p.get("key", ""), p.get("name", ""), p.get("projectTypeKey", "")))
            ))
            link_node_to_environment(graph, pid)

            # Project lead user node and edge
            lead = p.get("lead", {})
            lead_id = lead.get("accountId")
            if lead_id:
                uid = canonical_user_id(lead_id)
                if uid not in seen_user_ids:
                    display_name, user_email = fetch_user_details(lead_id, site_base, auth)
                    props = user_properties(
                        account_id=(lead_id or "").strip(),
                        display_name=(display_name or lead.get("displayName", "") or "").strip() or lead_id,
                        email=(user_email or lead.get("emailAddress", "") or "").strip(),
                        active=lead.get("active", True),
                    )
                    if not props["accountId"] or not props["displayName"]:
                        continue
                    graph.add_node(Node(
                        id=uid,
                        kinds=["CFUser"],
                        properties=Properties(**props)
                    ))
                    seen_user_ids.add(uid)
                link_node_to_environment(graph, uid)
                graph.add_edge(Edge(
                    uid,
                    pid,
                    "JLeads",
                    Properties()
                ))

            # Project permission scheme
            permissions = fetch_project_permissions(p['id'], site_base, auth)
            if permissions is None:  # None indicates 401/403, empty list means no permissions
                skipped_permission_schemes += 1
                permissions = []
            for perm in permissions:
                perm_raw = perm.get("permission")
                holder = perm.get("holder", {})
                holder_type = holder.get("type")
                holder_param = holder.get("parameter")
                if not (perm_raw and holder_type and holder_param):
                    continue
                perm_label = str(perm_raw)
                perm_key = perm_label.lower()
                perm_id = canonical_permission_id(perm_key)
                graph.add_node(
                    Node(
                        id=perm_id,
                        kinds=["JPermission"],
                        properties=Properties(
                            **permission_properties(perm_key, perm.get("description", ""))
                        ),
                    )
                )
                link_node_to_environment(graph, perm_id)
                if holder_type == "user":
                    uid = canonical_user_id(holder_param)
                    if uid not in seen_user_ids:
                        display_name, user_email = fetch_user_details(holder_param, site_base, auth)
                        props = user_properties(
                            account_id=(holder_param or "").strip(),
                            display_name=(display_name or holder_param).strip(),
                            email=(user_email or "").strip(),
                            active=True,
                        )
                        if not props["accountId"] or not props["displayName"]:
                            continue
                        graph.add_node(Node(
                            id=uid,
                            kinds=["CFUser"],
                            properties=Properties(**props)
                        ))
                        seen_user_ids.add(uid)
                    link_node_to_environment(graph, uid)
                    graph.add_edge(Edge(uid, perm_id, "CFHasPermission", Properties(permission=perm_key)))
                    # Also create CFPermissionGrantedTo edge (reverse)
                    graph.add_edge(Edge(perm_id, uid, "CFPermissionGrantedTo", Properties(permission=perm_key)))
                elif holder_type == "group":
                    group_node_id = _resolve_group_node(graph, holder_param)
                    if not group_node_id:
                        continue
                    link_node_to_environment(graph, group_node_id)
                    if group_node_id not in seen_group_names:
                        seen_group_names.add(group_node_id)
                    graph.add_edge(Edge(group_node_id, perm_id, "CFHasPermission", Properties(permission=perm_key)))
                    # Also create CFPermissionGrantedTo edge (reverse)
                    graph.add_edge(Edge(perm_id, group_node_id, "CFPermissionGrantedTo", Properties(permission=perm_key)))
                    # Inherited: for each user in this group, grant permission
                    group_member_cache = _lookup_group_members(graph, holder_param)
                    for uid in group_member_cache:
                        graph.add_edge(Edge(uid, perm_id, "CFHasPermission", Properties(permission=perm_key, inherited=True)))
                        graph.add_edge(Edge(perm_id, uid, "CFPermissionGrantedTo", Properties(permission=perm_key, inherited=True)))
                elif holder_type == "projectRole":
                    rid = canonical_role_id(str(p["id"]), str(holder_param), is_numeric=str(holder_param).isdigit())
                    graph.add_edge(Edge(rid, perm_id, "CFHasPermission", Properties(permission=perm_key)))
                    # Also create CFPermissionGrantedTo edge (reverse)
                    graph.add_edge(Edge(perm_id, rid, "CFPermissionGrantedTo", Properties(permission=perm_key)))
                    # Other types: 'applicationRole', 'authenticated', etc. can be handled if needed

            # --- Collect project roles and emit edges for BloodHound compatibility ---
            try:
                roles_url = f"{site_base}/rest/api/2/project/{p['id']}/role"
                rr = SESSION.get(roles_url, auth=auth, timeout=15)
                rr.raise_for_status()
                roles_map = rr.json()  # {"Administrators": ".../role/10002", ...}
                for role_name, role_url in roles_map.items():
                    # Create JRole node
                    role_identifier = role_url.rstrip('/').split('/')[-1]
                    role_node_id = canonical_role_id(str(p["id"]), role_identifier or role_name, is_numeric=role_identifier.isdigit() if role_identifier else False)
                    graph.add_node(Node(
                        id=role_node_id,
                        kinds=["JRole"],
                        properties=Properties(**role_properties(str(p.get("id", "")), role_identifier or role_name, role_name))
                    ))
                    link_node_to_environment(graph, role_node_id)
                    # Link JRole to JProject
                    graph.add_edge(Edge(
                        role_node_id,
                        pid,
                        "JRoleInProject",
                        Properties()
                    ))
                    # Fetch actors for this role
                    user_ids, group_names = fetch_role_members(role_url, auth)
                    for user_id in user_ids:
                        uid = canonical_user_id(user_id)
                        if uid not in seen_user_ids:
                            display_name, email = fetch_user_details(user_id, site_base, auth)
                            props = user_properties(user_id, (display_name or "").strip() or user_id, email or "", True)
                            if props["accountId"] and props["displayName"]:
                                graph.add_node(Node(id=uid, kinds=["CFUser"], properties=Properties(**props)))
                                seen_user_ids.add(uid)
                        link_node_to_environment(graph, uid)
                        graph.add_edge(Edge(
                            uid,
                            role_node_id,
                            "JAssignedToRole",
                            Properties()
                        ))
                        # If admin role, emit AdminTo edge
                        if role_name.lower() == "administrators":
                            graph.add_edge(Edge(
                                uid,
                                pid,
                                "AdminTo",
                                Properties()
                            ))
                    for group_name in group_names:
                        gid = _resolve_group_node(graph, group_name)
                        if not gid:
                            continue
                        link_node_to_environment(graph, gid)
                        graph.add_edge(Edge(
                            gid,
                            role_node_id,
                            "JGroupAssignedToRole",
                            Properties()
                        ))
                        # If admin role, emit AdminTo edge for all group members
                        if role_name.lower() == "administrators":
                            group_members = _lookup_group_members(graph, group_name)
                            for uid in group_members:
                                graph.add_edge(Edge(
                                    uid,
                                    pid,
                                    "AdminTo",
                                    Properties(inherited=True)
                                ))
            except requests.HTTPError as exc:
                status = getattr(exc.response, "status_code", None)
                if status in (401, 403):
                    skipped_role_collections += 1
                else:
                    LOG.warning(f"Failed to collect project roles for {p['id']}: {exc}")
            except Exception as e:
                LOG.warning(f"Failed to collect project roles for {p['id']}: {e}")

            # After adding project and permission nodes/edges, collect issues for this project
            project_issues = collect_issues(graph, project_id=p['id'], project_key=p.get('key')) or []
            for issue in project_issues:
                iid = canonical_issue_id(issue["id"])
                graph.add_edge(Edge(
                    pid,
                    iid,
                    "Contains",
                    Properties()
                ))

        LOG.info("Processed %d projects (total: %d) • page %d", len(projects), len(seen_project_ids), page_num)

        # Pagination
        if data.get("isLast", True):
            break
        start_at += max_results
        page_num += 1

    # Print summary of skipped operations
    total_projects = len(seen_project_ids)
    LOG.info("Project collection complete. Total: %d projects", total_projects)
    if skipped_permission_schemes > 0:
        LOG.warning(
            "Skipped %d project permission schemes (HTTP 401/403). "
            "API token lacks 'Administer Jira' permission. "
            "Run with an admin user to collect project-level permissions.",
            skipped_permission_schemes
        )
    if skipped_role_collections > 0:
        LOG.warning(
            "Skipped %d project role collections (HTTP 401/403). "
            "API token lacks sufficient permissions. "
            "Run with an admin user to collect project role memberships.",
            skipped_role_collections
        )
