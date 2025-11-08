import logging

from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

from utils.common import get_auth, SITE_BASE, PAGE_SIZE
from utils.http import get_session
from utils.environment import link_node_to_environment
from utils.normalizers import canonical_user_id, user_properties

LOG = logging.getLogger("AtlassianHound.users")

def run(graph):
    """
    Collect active Jira users via /rest/api/3/users/search and export as OpenGraph nodes.
    Node kind and properties strictly match model.json.
    """
    auth = get_auth()
    session = get_session()
    start = 0
    total_active = 0
    seen_ids = set()
    page_num = 1

    while True:
        url = f"{SITE_BASE}/rest/api/3/users/search"
        params = {"startAt": start, "maxResults": PAGE_SIZE}
        try:
            resp = session.get(url, auth=auth, params=params)
            resp.raise_for_status()
        except Exception as e:
            LOG.error("Failed to fetch users: %s", e)
            break
        users = resp.json()

        if not users:
            break

        added_this_page = 0
        for u in users:
            if not u.get("active", False):
                continue
            if (u.get("displayName") or "").strip().lower() == "former user":
                continue

            node_id = canonical_user_id(u.get("accountId", "").strip())
            if node_id in seen_ids:
                continue
            seen_ids.add(node_id)

            # Guarantee all required user properties are present and non-empty (except emailAddress, which may be empty)
            props = user_properties(
                account_id=u.get("accountId", "").strip(),
                display_name=u.get("displayName", "").strip(),
                email=u.get("emailAddress", "").strip(),
                active=bool(u.get("active", False)),
            )
            # Strict: required fields must be non-empty (except emailAddress)
            if not props["accountId"] or not props["displayName"]:
                continue
            node = Node(
                id=node_id,
                kinds=["CFUser"],
                properties=Properties(**props)
            )
            graph.add_node(node)
            link_node_to_environment(graph, node_id)
            total_active += 1
            added_this_page += 1

        LOG.info("Added %d users (total: %d) • page %d", added_this_page, total_active, page_num)

        if len(users) < PAGE_SIZE:
            break
        start += PAGE_SIZE
        page_num += 1

    LOG.info("User collection complete. Total: %d active users", total_active)
