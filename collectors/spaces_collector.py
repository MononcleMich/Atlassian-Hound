import logging
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
from utils.common import get_auth, SITE_BASE
from utils.http import get_session
from utils.environment import link_node_to_environment
from utils.normalizers import (
    canonical_group_id,
    canonical_space_id,
    canonical_user_id,
    group_properties,
    space_properties,
    user_properties,
)

LOG = logging.getLogger("AtlassianHound.spaces")

def run(graph):
    """
    Collect Confluence spaces using v2 API and their permissions, exporting as OpenGraph nodes/edges.
    Node/edge kinds and properties strictly match model.json.
    """
    auth = get_auth()
    base_url = f"{SITE_BASE}/wiki"
    url = f"{base_url}/api/v2/spaces"

    LOG.info("Starting space collection.")

    seen_space_ids = set()
    seen_user_ids = set()
    seen_group_ids = set()

    total_spaces = 0
    import concurrent.futures
    import threading
    # Set this value ONCE to control both threads and pool size
    MAX_PARALLEL = 10
    session = get_session()
    user_lock = threading.Lock()
    group_lock = threading.Lock()
    def fetch_permissions_for_space(s):
        sid = canonical_space_id(str(s["id"]))
        nodes_to_add = []
        edges_to_add = []
        perms_seen = {}
        perm_url = f"{base_url}/api/v2/spaces/{s['id']}/permissions"
        perm_next = perm_url
        while perm_next:
            try:
                pr = session.get(perm_next, auth=auth)
                pr.raise_for_status()
            except Exception as e:
                LOG.error("Failed to fetch permissions for space %s: %s", s["id"], e)
                break
            pdata = pr.json()
            for perm in pdata.get("results", []):
                principal = perm.get("principal")
                op = perm.get("operation")
                if not principal or not op:
                    continue
                # Node for principal if not seen
                if principal["type"] == "user":
                    pid = canonical_user_id(principal["id"])
                    if pid not in seen_user_ids:
                        props = user_properties(
                            account_id=principal.get("id", "").strip(),
                            display_name=principal.get("displayName", "").strip(),
                            email=principal.get("email", "").strip(),
                            active=principal.get("active", True),
                        )
                        if not props["accountId"] or not props["displayName"]:
                            continue
                        nodes_to_add.append(Node(
                            id=pid,
                            kinds=["CFUser"],
                            properties=Properties(**props)
                        ))
                elif principal["type"] == "group":
                    pid = canonical_group_id(principal.get("id"), principal.get("displayName"))
                    if pid not in seen_group_ids:
                        gprops = group_properties(
                            (principal.get("id", "") or "").strip() or (principal.get("displayName", "") or "").strip(),
                            (principal.get("displayName", "") or "").strip() or principal.get("id", ""),
                        )
                        if not gprops["groupId"] or not gprops["name"]:
                            continue
                        nodes_to_add.append(Node(
                            id=pid,
                            kinds=["CFGroup"],
                            properties=Properties(**gprops)
                        ))
                else:
                    continue
                # Aggregate permissions by (principal, space)
                edge_key = (pid, sid)
                perm_string = f"CF_{op['key']}_{op['targetType']}".lower()
                if edge_key not in perms_seen:
                    perms_seen[edge_key] = set()
                perms_seen[edge_key].add(perm_string)
            # Pagination for permissions
            perm_next_link = pdata.get("_links", {}).get("next")
            perm_next = f"{SITE_BASE}{perm_next_link}" if perm_next_link else None
        # Add the aggregated permission edges
        for (pid, sid2), perms in perms_seen.items():
            perms_list = sorted({p.lower() for p in perms if isinstance(p, str)})
            edges_to_add.append(Edge(
                pid,
                sid2,
                "CFHasPermission",
                Properties(permissions=perms_list)
            ))
            # Also create CFPermissionGrantedTo edge (reverse)
            edges_to_add.append(Edge(
                sid2,
                pid,
                "CFPermissionGrantedTo",
                Properties(permissions=perms_list)
            ))
            # --- BloodHound CE canonical edge mirroring ---
            perms_lower = perms_list
            if any("admin" in p for p in perms_lower):
                edges_to_add.append(Edge(
                    pid,
                    sid2,
                    "AdminTo",
                    Properties()
                ))
            if any("edit" in p or "write" in p for p in perms_lower):
                edges_to_add.append(Edge(
                    pid,
                    sid2,
                    "GenericWrite",
                    Properties()
                ))
        # Hierarchy: If this space has linked Jira projects, emit Contains edge
        linked_projects = s.get('linkedJiraProjects', [])
        for proj in linked_projects:
            pid = f"JProject:{proj['id']}"
            edges_to_add.append(Edge(
                sid,
                pid,
                "Contains",
                Properties()
            ))
        return (sid, nodes_to_add, edges_to_add)

    total_spaces = 0
    all_spaces = []
    while url:
        try:
            r = session.get(url, auth=auth)
            r.raise_for_status()
        except Exception as e:
            LOG.error("Failed to fetch spaces: %s", e)
            break
        data = r.json()
        spaces = data.get("results", [])
        if not spaces:
            break
        LOG.info("Fetched %d spaces in page", len(spaces))
        all_spaces.extend(spaces)
        next_link = data.get("_links", {}).get("next")
        url = f"{SITE_BASE}{next_link}" if next_link else None

    # Add all space nodes first
    seen_space_ids = set()
    for s in all_spaces:
        sid = canonical_space_id(str(s["id"]))
        if sid in seen_space_ids:
            continue
        seen_space_ids.add(sid)
        # Add all required space properties
        node = Node(
            id=sid,
            kinds=["CFSpace"],
            properties=Properties(**space_properties(str(s.get("id", "")), s.get("key", ""), s.get("name", ""), s.get("type", "")))
        )
        graph.add_node(node)
        link_node_to_environment(graph, sid)
        total_spaces += 1

    # Now fetch permissions in parallel
    LOG.info("Fetching permissions for %d spaces in parallel...", len(all_spaces))
    from collections import defaultdict
    seen_user_ids = set()
    seen_group_ids = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL) as executor:
        futures = [executor.submit(fetch_permissions_for_space, s) for s in all_spaces]
        for future in concurrent.futures.as_completed(futures):
            sid, nodes_to_add, edges_to_add = future.result()
            for node in nodes_to_add:
                if node.id.startswith("CFUser:"):
                    with user_lock:
                        if node.id not in seen_user_ids:
                            graph.add_node(node)
                            seen_user_ids.add(node.id)
                        link_node_to_environment(graph, node.id)
                elif node.id.startswith("CFGroup:"):
                    with group_lock:
                        if node.id not in seen_group_ids:
                            graph.add_node(node)
                            seen_group_ids.add(node.id)
                        link_node_to_environment(graph, node.id)
            for edge in edges_to_add:
                if not isinstance(edge, Edge):
                    LOG.error(f"[EXPORT VALIDATION] Non-Edge object in edges_to_add: type={type(edge)}, value={edge}")
                    continue
                graph.add_edge(edge)
    LOG.info("Space collection complete. Total spaces: %d", total_spaces)

    LOG.info("Space collection complete. Total spaces: %d", total_spaces)
