import logging

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

from utils.environment import link_node_to_environment
from utils.common import SITE_BASE, get_auth
from utils.http import get_session
from utils.normalizers import canonical_user_id, user_properties


LOG = logging.getLogger("AtlassianHound.watchers")


def run(graph) -> None:
    auth = get_auth()
    session = get_session()
    issue_nodes = [
        node.to_dict()
        for node in getattr(graph, "nodes", {}).values()
        if "JIssue" in (node.to_dict().get("kinds") or [])
    ]
    for issue in issue_nodes:
        issue_id = issue.get("id")
        props = issue.get("properties") or {}
        issue_key = props.get("key")
        if not issue_key or not issue_id:
            continue
        link_node_to_environment(graph, issue_id)
        url = f"{SITE_BASE}/rest/api/3/issue/{issue_key}/watchers"
        try:
            resp = session.get(url, auth=auth)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
        except Exception as exc:
            LOG.debug("Watchers lookup failed for %s: %s", issue_key, exc)
            continue
        data = resp.json()
        for watcher in data.get("watchers", []):
            account_id = watcher.get("accountId")
            if not account_id:
                continue
            user_id = canonical_user_id(account_id)
            if user_id not in getattr(graph, "nodes", {}):
                graph.add_node(
                    Node(
                        id=user_id,
                        kinds=["CFUser"],
                        properties=Properties(**user_properties(account_id, watcher.get("displayName", account_id), watcher.get("emailAddress", ""), watcher.get("active", True))),
                    )
                )
            link_node_to_environment(graph, user_id)
            graph.add_edge(Edge(user_id, issue_id, "JWatched", Properties()))
