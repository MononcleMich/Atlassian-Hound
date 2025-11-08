from __future__ import annotations

import logging
import os
import time
import random
from typing import Optional

from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties

from utils.common import get_auth, SITE_BASE, PAGE_SIZE, ATLASSIAN_API_BASE, ATLASSIAN_ORG_ID
from utils.environment import link_node_to_environment
from utils.http import get_session
from utils.normalizers import (
    canonical_team_id,
    canonical_user_id,
    team_properties,
    user_properties,
)

LOG = logging.getLogger("AtlassianHound.teams")
if os.environ.get("ATLASSIANHOUND_DEBUG") == "1":
    LOG.setLevel(logging.DEBUG)
else:
    LOG.setLevel(logging.INFO)

_SESSION = get_session()


def fetch_user_details(account_id, site_base, auth):
    """Fetch displayName and email for a user from Confluence endpoint."""
    url = f"{site_base}/wiki/rest/api/user?accountId={account_id}"
    retries = 0
    while retries < 5:
        try:
            r = _SESSION.get(url, auth=auth)
            if r.status_code in (429, 401):
                delay = min(60, (2 ** retries) + random.uniform(0, 1))
                time.sleep(delay)
                retries += 1
                continue
            r.raise_for_status()
            data = r.json()
            return data.get("displayName"), data.get("email")
        except Exception as e:
            LOG.warning(f"Failed to enrich user {account_id}: {e}")
            delay = min(60, (2 ** retries) + random.uniform(0, 1))
            time.sleep(delay)
            retries += 1
    return None, None

def run(graph):
    # debug_members_logged removed
    """
    Collect Atlassian teams and their memberships, exporting as OpenGraph nodes/edges.
    Node/edge kinds and properties strictly match model.json.
    """
    org_id = os.environ.get("ATLASSIAN_ORG_ID")
    email = os.environ.get("ATLASSIAN_EMAIL")
    api_token = os.environ.get("ATLASSIAN_API_TOKEN")
    site_base = os.environ.get("ATLASSIAN_SITE_BASE")

    if not org_id:
        LOG.critical("ATLASSIAN_ORG_ID is not set in the environment.")
        return
    if not email:
        LOG.critical("ATLASSIAN_EMAIL is not set in the environment.")
        return
    if not api_token:
        LOG.critical("ATLASSIAN_API_TOKEN is not set in the environment.")
        return
    if not site_base:
        LOG.critical("ATLASSIAN_SITE_BASE is not set in the environment.")
        return

    auth = (email, api_token)
    headers = {
        "Accept": "*/*",
        "Content-Type": "application/json"
    }

    # Use gateway endpoint for team list
    gateway_base = f"{site_base}/gateway"
    teams_url = f"{gateway_base}/api/public/teams/v1/org/{org_id}/teams/"

    LOG.info("Starting teams collection.")

    seen_team_ids = set()
    seen_user_ids = set()
    total_teams = 0
    total_members = 0

    url = teams_url
    after = None
    last_after = None
    while True:
        params = {}
        if after:
            params["cursor"] = after
        try:
            r = _SESSION.get(url, headers=headers, auth=auth, params=params)
            r.raise_for_status()
        except Exception as e:
            LOG.error("Failed to fetch teams: %s", e)
            return

        data = r.json()
        teams = data.get("entities", [])
        LOG.info("Fetched %d teams in page", len(teams))
        if not teams:
            LOG.warning("No teams found in response.")
            break

        for t in teams:
            team_id = (t.get("teamId") or "").strip()
            display_name = (t.get("displayName") or team_id).strip()
            description = (t.get("description") or "").strip()
            organization_id = (t.get("organizationId") or "").strip()
            required_fields = {
                "teamId": team_id,
                "displayName": display_name,
                "organizationId": organization_id
            }
            missing = [k for k, v in required_fields.items() if not v]
            tid = canonical_team_id(team_id)
            if tid in seen_team_ids:
                continue
            if missing:
                LOG.warning(f"Skipping team {team_id} due to missing required fields: {missing}. Full team object: {t}")
                continue
            seen_team_ids.add(tid)
            team_props = team_properties(team_id, display_name, description, organization_id)
            graph.add_node(Node(
                id=tid,
                kinds=["CFTeam"],
                properties=Properties(**team_props)
            ))
            link_node_to_environment(graph, tid)
            # Debug log removed
            total_teams += 1
            _enrich_team_roles(graph, auth, tid, org_id, t.get("teamId"))

            # Use api.atlassian.com for memberships
            members_url = f"https://api.atlassian.com/public/teams/v1/org/{org_id}/teams/{t['teamId']}/members"
            members_after = None
            while True:
                payload = {"first": 40}
                if members_after:
                    payload["after"] = members_after
                retries = 0
                mr = None
                while retries < 5:
                    try:
                        mr = _SESSION.post(members_url, headers=headers, auth=auth, json=payload)
                        if mr.status_code in (429, 401):
                            delay = min(60, (2 ** retries) + random.uniform(0, 1))
                            time.sleep(delay)
                            retries += 1
                            continue
                        mr.raise_for_status()
                        break
                    except Exception as e:
                        LOG.error("Failed to fetch members for team %s: %s", t["teamId"], e)
                        delay = min(60, (2 ** retries) + random.uniform(0, 1))
                        time.sleep(delay)
                        retries += 1
                        if retries >= 5:
                            break
                if mr is None:
                    break
                mdata = mr.json()
                members = mdata.get("results", [])
                LOG.info("[OpenGraph] Fetched %d members for team '%s'", len(members), t.get("displayName", t["teamId"]))
                if not members:
                    LOG.info(f"No members found for team '{t.get('displayName', t['teamId'])}'. Full response: {mdata}")
                for m in members:
                    account_id = m.get("accountId")
                    if not account_id:
                        continue
                    uid = canonical_user_id(account_id)
                    if uid not in seen_user_ids:
                        display_name, user_email = fetch_user_details(account_id, site_base, auth)
                        display = (display_name or m.get("displayName", "") or "").strip()
                        if not display:
                            display = account_id
                        props = user_properties(
                            account_id=(account_id or "").strip(),
                            display_name=display,
                            email=(user_email or m.get("email", "") or "").strip(),
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
                    # Always create CFMemberOfTeam edge
                    graph.add_edge(Edge(
                        uid,
                        tid,
                        "CFMemberOfTeam",
                        Properties()
                    ))
                    # Also create CFTeamHasMember edge (reverse)
                    graph.add_edge(Edge(
                        tid,
                        uid,
                        "CFTeamHasMember",
                        Properties()
                    ))
                page_info = mdata.get("pageInfo", {})
                if page_info.get("hasNextPage"):
                    members_after = page_info.get("endCursor")
                else:
                    break

        # Paging: get next cursor, break if not advancing
        page_info = data.get("pageInfo", {})
        next_after = page_info.get("endCursor")
        has_next = page_info.get("hasNextPage", False)
        if not has_next or not next_after or next_after == after:
            break
        last_after = after
        after = next_after
    LOG.info(f"Total CFTeam nodes added: {total_teams}")


def _enrich_team_roles(graph, auth, team_node_id: str, org_id: str, team_id: str) -> None:
    if not org_id or not team_id:
        return
    detail_url = f"{ATLASSIAN_API_BASE}/public/teams/v1/org/{org_id}/teams/{team_id}"
    try:
        resp = _SESSION.get(detail_url, auth=auth)
        if resp.status_code == 404:
            return
        resp.raise_for_status()
    except Exception as exc:
        LOG.debug("Failed to fetch detail for team %s: %s", team_id, exc)
        return
    detail = resp.json()
    roles = detail.get("roles", {})
    owners = roles.get("owners", []) or []
    managers = roles.get("managers", []) or []
    _link_special_members(graph, team_node_id, owners, "CFTeamOwner")
    _link_special_members(graph, team_node_id, managers, "CFTeamManager")


def _link_special_members(graph, team_node_id: str, members: list[dict], edge_kind: str) -> None:
    for member in members:
        account_id = member.get("accountId")
        if not account_id:
            continue
        user_id = canonical_user_id(account_id)
        if user_id not in getattr(graph, "nodes", {}):
            graph.add_node(
                Node(
                    id=user_id,
                    kinds=["CFUser"],
                    properties=Properties(**user_properties(account_id, member.get("displayName", account_id), member.get("email", ""), True)),
                )
            )
        link_node_to_environment(graph, user_id)
        graph.add_edge(Edge(user_id, team_node_id, edge_kind, Properties()))
