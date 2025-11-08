"""
AtlassianHound - Issue Security Schemes Collector

Collects Jira issue security schemes and security levels to identify:
- Hidden access layers (security levels bypass standard permissions)
- Shadow authorization (unexpected users with security level access)
- Data classification (security level names reveal sensitivity)
- Privilege escalation paths (security level membership = high-value access)

Security Schemes are CRITICAL for offensive security because they:
1. Create invisible access control layers
2. Grant access that bypasses project permissions
3. Are often forgotten by admins (shadow privileges)
4. Contain sensitive data classifications ("Confidential", "Executive", "Internal")
"""

import logging
import os
from typing import Dict, List, Optional, Set

import requests

from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
from utils.common import get_auth, SITE_BASE
from utils.environment import link_node_to_environment
from utils.http import get_session, handle_http_error
from utils.normalizers import (
    canonical_user_id,
    canonical_group_id,
    canonical_role_id,
    canonical_project_id,
    canonical_security_scheme_id,
    canonical_security_level_id,
    user_properties,
    group_properties,
    security_scheme_properties,
    security_level_properties,
)

LOG = logging.getLogger("AtlassianHound.security_schemes")
SESSION = get_session()


def run(graph):
    """
    Collect Jira issue security schemes and security levels.

    Creates:
    - JSecurityScheme nodes for each security scheme
    - JSecurityLevel nodes for each security level in a scheme
    - JHasSecurityLevel edges (CFUser/CFGroup/JRole → JSecurityLevel)
    - CanManageSecurityScheme edges (CFUser → JSecurityScheme) - HIGH VALUE
    - JSecurityLevelInScheme edges (JSecurityLevel → JSecurityScheme)

    Security Impact:
    - Security levels create hidden access control layers
    - Users with security level access can see issues others cannot
    - Security level names reveal data classification
    - Managers of security schemes are high-value targets
    """
    site_base = os.environ.get("ATLASSIAN_SITE_BASE")
    if not site_base:
        LOG.critical("ATLASSIAN_SITE_BASE not configured.")
        return

    auth = get_auth()

    # Track statistics
    total_schemes = 0
    total_levels = 0
    high_value_levels = 0  # Levels with names like "confidential", "executive", etc.
    security_managers = set()

    try:
        # Fetch all issue security schemes
        schemes_url = f"{site_base}/rest/api/3/issuesecurityschemes"
        resp = SESSION.get(schemes_url, auth=auth, timeout=30)

        if resp.status_code == 401:
            LOG.warning("401 Unauthorized - API token lacks 'Administer Jira' permission. Cannot collect security schemes.")
            return

        if resp.status_code == 403:
            LOG.warning("403 Forbidden - API token lacks 'Administer Jira' permission. Cannot collect security schemes.")
            return

        resp.raise_for_status()
        data = resp.json()

    except requests.exceptions.RequestException as e:
        LOG.error(f"Failed to fetch security schemes: {e}")
        return

    # Process security schemes
    schemes = data.get("issueSecuritySchemes", [])

    if not schemes:
        LOG.info("No issue security schemes found in this Jira instance.")
        return

    LOG.info(f"Found {len(schemes)} issue security schemes. Analyzing...")

    for scheme in schemes:
        scheme_id = scheme.get("id")
        if not scheme_id:
            continue

        total_schemes += 1
        scheme_node_id = canonical_security_scheme_id(str(scheme_id))

        # Create JSecurityScheme node
        scheme_props = security_scheme_properties(
            scheme_id=str(scheme_id),
            name=scheme.get("name", f"Scheme-{scheme_id}"),
            description=scheme.get("description", ""),
            default_level_id=str(scheme.get("defaultSecurityLevelId", "")),
        )

        graph.add_node(Node(
            id=scheme_node_id,
            kinds=["JSecurityScheme"],
            properties=Properties(**scheme_props)
        ))
        link_node_to_environment(graph, scheme_node_id)

        # Fetch security levels for this scheme
        levels = scheme.get("levels", [])

        if not levels:
            # Try fetching levels from dedicated endpoint
            try:
                levels_url = f"{site_base}/rest/api/3/issuesecurityschemes/{scheme_id}"
                resp = SESSION.get(levels_url, auth=auth, timeout=15)
                resp.raise_for_status()
                scheme_detail = resp.json()
                levels = scheme_detail.get("levels", [])
            except Exception as e:
                LOG.debug(f"Could not fetch levels for scheme {scheme_id}: {e}")
                continue

        # Process security levels
        for level in levels:
            level_id = level.get("id")
            if not level_id:
                continue

            total_levels += 1
            level_node_id = canonical_security_level_id(str(scheme_id), str(level_id))
            level_name = level.get("name", f"Level-{level_id}")

            # Check if this is a high-value level based on name
            is_high_value = any(keyword in level_name.lower() for keyword in [
                "confidential", "secret", "restricted", "executive", "internal",
                "private", "sensitive", "admin", "security", "critical"
            ])

            if is_high_value:
                high_value_levels += 1

            # Create JSecurityLevel node
            level_props = security_level_properties(
                level_id=str(level_id),
                scheme_id=str(scheme_id),
                name=level_name,
                description=level.get("description", ""),
                is_default=str(level_id) == scheme.get("defaultSecurityLevelId", ""),
                is_high_value=is_high_value,
            )

            graph.add_node(Node(
                id=level_node_id,
                kinds=["JSecurityLevel"],
                properties=Properties(**level_props)
            ))
            link_node_to_environment(graph, level_node_id)

            # Link level to scheme
            graph.add_edge(Edge(
                level_node_id,
                scheme_node_id,
                "JSecurityLevelInScheme",
                Properties()
            ))

            # Process security level members (who has access to this level)
            _process_level_members(graph, site_base, auth, scheme_id, level_id, level_node_id, level_name)

    # Identify users who can manage security schemes (Administer Jira permission)
    _identify_security_scheme_managers(graph, site_base, auth, total_schemes)

    # Log summary
    LOG.info(
        f"Security schemes collection complete. "
        f"Schemes: {total_schemes}, Levels: {total_levels}, High-value levels: {high_value_levels}"
    )

    if high_value_levels > 0:
        LOG.warning(
            f"⚠️  Found {high_value_levels} HIGH-VALUE security levels "
            f"(names contain 'confidential', 'executive', 'restricted', etc.). "
            "These grant access to sensitive issues. Investigate immediately!"
        )


def _process_level_members(
    graph,
    site_base: str,
    auth,
    scheme_id: str,
    level_id: str,
    level_node_id: str,
    level_name: str
):
    """
    Process security level members (users, groups, roles with access to this level).
    Creates JHasSecurityLevel edges.
    """
    try:
        # Fetch security level members
        members_url = f"{site_base}/rest/api/3/issuesecurityschemes/{scheme_id}/members"
        params = {"levelId": level_id}
        resp = SESSION.get(members_url, auth=auth, params=params, timeout=15)

        if resp.status_code in (401, 403):
            LOG.debug(f"Cannot fetch members for security level {level_id} (insufficient permissions)")
            return

        resp.raise_for_status()
        data = resp.json()

        members = data.get("values", [])

        for member in members:
            holder = member.get("holder", {})
            holder_type = holder.get("type")

            if holder_type == "user":
                # User has access to this security level
                user_data = holder.get("user", {})
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

                    # Create JHasSecurityLevel edge (HIGH VALUE)
                    graph.add_edge(Edge(
                        user_node_id,
                        level_node_id,
                        "JHasSecurityLevel",
                        Properties(
                            level_name=level_name,
                            description=f"Can view issues at security level '{level_name}'"
                        )
                    ))

            elif holder_type == "group":
                # Group has access to this security level
                group_data = holder.get("group", {})
                group_name = group_data.get("name")

                if group_name:
                    group_node_id = canonical_group_id(name=group_name)

                    # Ensure group node exists
                    if group_node_id not in graph.nodes:
                        props = group_properties(
                            group_id=group_name,
                            name=group_name,
                        )
                        graph.add_node(Node(
                            id=group_node_id,
                            kinds=["CFGroup"],
                            properties=Properties(**props)
                        ))
                        link_node_to_environment(graph, group_node_id)

                    # Create JHasSecurityLevel edge
                    graph.add_edge(Edge(
                        group_node_id,
                        level_node_id,
                        "JHasSecurityLevel",
                        Properties(
                            level_name=level_name,
                            description=f"Can view issues at security level '{level_name}'"
                        )
                    ))

                    # Propagate to group members (if we have group membership data)
                    _propagate_security_level_to_group_members(graph, group_node_id, level_node_id, level_name)

            elif holder_type == "projectRole":
                # Project role has access to this security level
                role_data = holder.get("projectRole", {})
                role_name = role_data.get("name")

                # Note: Security level role membership is project-specific
                # We'd need to know which project to create the proper JRole node
                # For now, log and skip (can be enhanced later with project context)
                LOG.debug(f"Security level {level_id} has project role member: {role_name}")

    except Exception as e:
        LOG.debug(f"Could not process members for security level {level_id}: {e}")


def _propagate_security_level_to_group_members(
    graph,
    group_node_id: str,
    level_node_id: str,
    level_name: str
):
    """
    Propagate security level access to all group members.
    Creates inherited JHasSecurityLevel edges.
    """
    # Find all users who are members of this group
    for edge in graph.edges.values():
        if edge.kind == "CFMemberOfGroup" and edge.end_node == group_node_id:
            user_node_id = edge.start_node

            # Create inherited security level access edge
            graph.add_edge(Edge(
                user_node_id,
                level_node_id,
                "JHasSecurityLevel",
                Properties(
                    level_name=level_name,
                    inherited=True,
                    via_group=group_node_id,
                    description=f"Inherited via group membership: can view issues at security level '{level_name}'"
                )
            ))


def _identify_security_scheme_managers(graph, site_base: str, auth, scheme_count: int):
    """
    Identify users with 'Administer Jira' permission who can manage security schemes.
    These users are HIGH-VALUE targets for privilege escalation.
    """
    if scheme_count == 0:
        return

    try:
        # Get current user permissions
        perms_url = f"{site_base}/rest/api/3/permissions"
        resp = SESSION.get(perms_url, auth=auth, timeout=15)

        if resp.status_code in (401, 403):
            LOG.debug("Cannot fetch permissions (insufficient rights).")
            return

        resp.raise_for_status()
        permissions_data = resp.json()

        # Check if current user can administer Jira
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

                # Create HIGH-VALUE edge: CanManageSecurityScheme
                graph.add_edge(Edge(
                    user_node_id,
                    jira_instance_id,
                    "CanManageSecurityScheme",
                    Properties(
                        permission="ADMINISTER",
                        high_value=True,
                        description="Can create/modify/delete security schemes (controls hidden access layer)"
                    )
                ))

                LOG.info(f"Identified security scheme manager: {user_data.get('displayName')} (HIGH VALUE TARGET)")

    except Exception as e:
        LOG.debug(f"Could not identify security scheme managers: {e}")
