"""
AtlassianHound - Webhooks Collector

Collects registered Jira webhooks to identify:
- Persistence mechanisms (webhooks survive password changes)
- Data exfiltration channels (webhooks send data to external URLs)
- C2 communication channels
- High-value targets (users who can manage webhooks)

Webhooks are critical for offensive security because they:
1. Provide persistence - survive credential rotation
2. Enable data exfiltration - real-time event streaming to attacker server
3. Low detection - often not monitored or audited
4. Privilege escalation - webhook management = admin-level control
"""

import logging
import os
from typing import Optional

import requests

from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
from utils.common import get_auth, SITE_BASE
from utils.environment import link_node_to_environment
from utils.http import get_session, handle_http_error
from utils.normalizers import (
    canonical_user_id,
    canonical_webhook_id,
    user_properties,
    webhook_properties,
)

LOG = logging.getLogger("AtlassianHound.webhooks")
SESSION = get_session()


def run(graph):
    """
    Collect Jira webhooks and their relationships.

    Creates:
    - Webhook nodes for each registered webhook
    - RegisteredWebhook edges (CFUser → Webhook)
    - CanManageWebhooks edges (CFUser → JiraInstance) - HIGH VALUE

    Security Impact:
    - Webhooks are persistence mechanisms
    - Webhooks can exfiltrate data to external servers
    - Users who can manage webhooks are high-value targets
    """
    site_base = os.environ.get("ATLASSIAN_SITE_BASE")
    if not site_base:
        LOG.critical("ATLASSIAN_SITE_BASE not configured.")
        return

    auth = get_auth()
    webhooks_url = f"{site_base}/rest/api/3/webhook"

    # Track statistics
    total_webhooks = 0
    external_webhooks = 0  # Webhooks to non-Atlassian domains
    webhook_creators = set()

    try:
        # Fetch all webhooks (requires Administer Jira permission)
        resp = SESSION.get(webhooks_url, auth=auth, timeout=30)

        if resp.status_code == 401:
            LOG.warning("401 Unauthorized - API token lacks 'Administer Jira' permission. Cannot collect webhooks.")
            return

        if resp.status_code == 403:
            LOG.warning("403 Forbidden - API token lacks 'Administer Jira' permission. Cannot collect webhooks.")
            return

        resp.raise_for_status()
        data = resp.json()

    except requests.exceptions.RequestException as e:
        LOG.error(f"Failed to fetch webhooks: {e}")
        return

    # Process webhooks
    webhooks = data.get("values", [])

    if not webhooks:
        LOG.info("No webhooks registered in this Jira instance.")
        return

    LOG.info(f"Found {len(webhooks)} registered webhooks. Analyzing...")

    for webhook in webhooks:
        webhook_id = webhook.get("id")
        if not webhook_id:
            continue

        total_webhooks += 1
        webhook_node_id = canonical_webhook_id(str(webhook_id))

        # Extract webhook properties
        url = webhook.get("url", "")
        events = webhook.get("events", [])
        scope = webhook.get("scope", {})
        enabled = webhook.get("enabled", True)

        # Check if webhook points to external domain (potential exfiltration)
        is_external = not any(domain in url.lower() for domain in ["atlassian.net", "atlassian.com"])
        if is_external:
            external_webhooks += 1

        # Create Webhook node
        props = webhook_properties(
            webhook_id=str(webhook_id),
            name=webhook.get("name", f"Webhook-{webhook_id}"),
            url=url,
            events=events,
            enabled=enabled,
            scope_type=scope.get("type", ""),
            scope_id=scope.get("id", ""),
            is_external=is_external,
        )

        graph.add_node(Node(
            id=webhook_node_id,
            kinds=["Webhook"],
            properties=Properties(**props)
        ))
        link_node_to_environment(graph, webhook_node_id)

        # Create RegisteredWebhook edge (Webhook -> JiraInstance)
        # This allows queries to find all webhooks registered to the instance
        jira_instance_id = "JiraInstance:global"
        graph.add_edge(Edge(
            webhook_node_id,
            jira_instance_id,
            "RegisteredWebhook",
            Properties(
                webhook_id=str(webhook_id),
                is_external=is_external,
                enabled=enabled
            )
        ))

        # Mark external webhooks as high-value for investigation
        if is_external:
            graph.add_node(Node(
                id=webhook_node_id,
                kinds=["Webhook"],
                properties=Properties(**{**props, "high_value": True})
            ))

    # Find users with webhook management permissions
    # Users with "Administer Jira" permission can manage webhooks
    _identify_webhook_managers(graph, site_base, auth)

    # Log summary
    LOG.info(f"Webhook collection complete. Total: {total_webhooks}, External: {external_webhooks}")

    if external_webhooks > 0:
        LOG.warning(
            f"⚠️  Found {external_webhooks} webhooks pointing to EXTERNAL domains. "
            "These are potential data exfiltration channels or persistence mechanisms. "
            "Investigate immediately!"
        )


def _identify_webhook_managers(graph, site_base: str, auth):
    """
    Identify users with 'Administer Jira' permission who can manage webhooks.
    These users are HIGH-VALUE targets for privilege escalation.
    """
    try:
        # Get global permissions
        perms_url = f"{site_base}/rest/api/3/permissions"
        resp = SESSION.get(perms_url, auth=auth, timeout=15)

        if resp.status_code in (401, 403):
            LOG.debug("Cannot fetch global permissions (insufficient rights). Skipping webhook manager identification.")
            return

        resp.raise_for_status()
        permissions_data = resp.json()

        # Check if current user can administer Jira (they can manage webhooks)
        has_admin = permissions_data.get("permissions", {}).get("ADMINISTER", {}).get("havePermission", False)

        if has_admin:
            # Get current user info
            myself_url = f"{site_base}/rest/api/3/myself"
            resp = SESSION.get(myself_url, auth=auth, timeout=10)
            resp.raise_for_status()
            user_data = resp.json()

            account_id = user_data.get("accountId")
            if account_id:
                user_node_id = canonical_user_id(account_id)

                # Ensure user node exists
                if user_node_id not in graph.nodes:
                    props = user_properties(
                        account_id=account_id,
                        display_name=user_data.get("displayName", account_id),
                        email=user_data.get("emailAddress", ""),
                        active=user_data.get("active", True),
                    )
                    graph.add_node(Node(
                        id=user_node_id,
                        kinds=["CFUser"],
                        properties=Properties(**props)
                    ))
                    link_node_to_environment(graph, user_node_id)

                # Create JiraInstance node if not exists
                jira_instance_id = "JiraInstance:global"
                if jira_instance_id not in graph.nodes:
                    graph.add_node(Node(
                        id=jira_instance_id,
                        kinds=["JiraInstance"],
                        properties=Properties(
                            objectid="global",
                            name="Jira Cloud",
                            url=site_base,
                        )
                    ))
                    link_node_to_environment(graph, jira_instance_id)

                # Create HIGH-VALUE edge: CanManageWebhooks
                graph.add_edge(Edge(
                    user_node_id,
                    jira_instance_id,
                    "CanManageWebhooks",
                    Properties(
                        permission="ADMINISTER",
                        high_value=True,
                        description="Can create/modify/delete webhooks (persistence & exfiltration capability)"
                    )
                ))

                LOG.info(f"Identified webhook manager: {user_data.get('displayName')} (HIGH VALUE TARGET)")

    except Exception as e:
        LOG.debug(f"Could not identify webhook managers: {e}")
