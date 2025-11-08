import logging
from typing import Dict, Iterable

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

import requests

from utils.common import SITE_BASE, get_auth
from utils.environment import link_node_to_environment
from utils.http import get_session, handle_http_error
from utils.normalizers import (
    canonical_project_id,
    canonical_service_desk_id,
    canonical_user_id,
    service_desk_properties,
    user_properties,
)


LOG = logging.getLogger("AtlassianHound.jsm")


def run(graph) -> None:
    auth = get_auth()
    session = get_session()
    desks = _fetch_service_desks(session, auth)
    if not desks:
        LOG.info("No service desks discovered.")
        return
    for desk in desks:
        desk_id = str(desk.get("id"))
        project = desk.get("project") or {}
        project_id = canonical_project_id(str(project.get("id") or desk_id))
        service_desk_node = canonical_service_desk_id(desk_id)
        graph.add_node(
            Node(
                id=service_desk_node,
                kinds=["JServiceDesk"],
                properties=Properties(
                    **service_desk_properties(
                        desk_id,
                        desk.get("name", ""),
                        str(project.get("id", "")),
                        project.get("key", ""),
                    )
                ),
            )
        )
        link_node_to_environment(graph, service_desk_node)
        graph.add_edge(
            Edge(
                service_desk_node,
                project_id,
                "BackedByProject",
                Properties(),
            )
        )
        _link_agents(graph, session, auth, desk_id, service_desk_node)


def _fetch_service_desks(session, auth) -> Iterable[Dict]:
    url = f"{SITE_BASE}/rest/servicedeskapi/servicedesk"
    params = {"start": 0, "limit": 50}
    desks = []
    headers = {"Accept": "application/json"}
    while True:
        try:
            resp = session.get(url, auth=auth, headers=headers, params=params)
        except requests.RequestException as exc:
            LOG.error("Service desk enumeration failed: %s", exc)
            break
        if resp.status_code == 404:
            LOG.info("Jira Service Management API not detected. Skipping.")
            return []
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            handle_http_error(resp, "JSM service desk enumeration")
            break
        data = resp.json()
        desks.extend(data.get("values", []))
        if not data.get("isLastPage"):
            params["start"] = data.get("start", 0) + data.get("limit", 50)
        else:
            break
    return desks


def _link_agents(graph, session, auth, desk_id: str, desk_node_id: str) -> None:
    url = f"{SITE_BASE}/rest/servicedeskapi/servicedesk/{desk_id}/agent"
    params = {"start": 0, "limit": 50}
    headers = {"Accept": "application/json"}
    while True:
        try:
            resp = session.get(url, auth=auth, headers=headers, params=params)
        except requests.RequestException as exc:
            LOG.error("Failed to enumerate agents for service desk %s: %s", desk_id, exc)
            break
        if resp.status_code == 404:
            LOG.info("Service desk %s not accessible (JSM not enabled or insufficient rights). Skipping.", desk_id)
            return
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            handle_http_error(resp, f"JSM agent enumeration for {desk_id}")
            break
        data = resp.json()
        for agent in data.get("values", []):
            account_id = agent.get("accountId")
            if not account_id:
                continue
            user_id = canonical_user_id(account_id)
            if user_id not in getattr(graph, "nodes", {}):
                graph.add_node(
                    Node(
                        id=user_id,
                        kinds=["CFUser"],
                        properties=Properties(**user_properties(account_id, agent.get("displayName", account_id), agent.get("emailAddress", ""), True)),
                    )
                )
            link_node_to_environment(graph, user_id)
            graph.add_edge(Edge(user_id, desk_node_id, "JServiceDeskAgent", Properties()))
            graph.add_edge(Edge(user_id, desk_node_id, "AdminTo", Properties(source="service-desk")))
        if data.get("isLastPage"):
            break
        params["start"] = data.get("start", 0) + data.get("limit", 50)
