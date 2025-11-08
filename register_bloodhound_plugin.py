#!/usr/bin/env python3
"""
Register AtlassianHound (Confluence + Jira) as a BloodHound plugin with full attack pathing.

This makes Confluence/Jira nodes first-class citizens in BloodHound with:
- Native pathfinding through Atlassian permissions
- Cross-platform sync: AD ↔ Atlassian ↔ Azure
- Privilege zone integration (Confluence/Jira admins = Tier 0)
- Dynamic UI tabs and pre-built queries

Compatible with SpecterOps design requirements:
-  Directional edges (attack flow)
-  Unique identifiers (GUIDs/UUIDs)
-  Distinct edge names (CF*/J* prefixes)
-  Multi-node paths (complex attack chains)
-  Traversable edges (pathfinding enabled)

Usage:
    export BLOODHOUND_TOKEN="your-token"
    python register_bloodhound_plugin.py
"""

import requests
import json
import os
from typing import Dict, Any

# BloodHound Configuration
BLOODHOUND_URL = os.getenv("BLOODHOUND_URL", "http://localhost:8080")
BLOODHOUND_TOKEN = os.getenv("BLOODHOUND_TOKEN", "")

# Plugin metadata
PLUGIN_ID = "atlassian"
PLUGIN_NAME = "Atlassian Cloud (Confluence + Jira)"
PLUGIN_VERSION = "1.0.0"

def get_auth_headers() -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {BLOODHOUND_TOKEN}"
    }

def register_plugin() -> None:
    """Register AtlassianHound plugin with ALL edges marked as traversable."""

    registration_payload = {
        "plugin_id": PLUGIN_ID,
        "plugin_name": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "cross_platform": True,  # Enables AD/Azure sync
        "config": {
            "privilege_zone": True,  # Atlassian admins = Tier 0
            "searchable": True,
            "icon_set": "font-awesome"
        },

        # Node types - from your model.json
        "node_kinds": [
            {
                "kind_name": "CFUser",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-user", "color": "#1976d2"},
                    "description": "Atlassian Cloud user account",
                    "privilege_zone": True,  # Users with admin perms = Tier 0
                    "searchable": True
                }
            },
            {
                "kind_name": "CFGroup",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-users", "color": "#8e24aa"},
                    "description": "Atlassian organization-level group"
                }
            },
            {
                "kind_name": "CFTeam",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-users", "color": "#00897b"},
                    "description": "Atlassian Team (organizational unit)"
                }
            },
            {
                "kind_name": "CFSpace",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-book", "color": "#ffb300"},
                    "description": "Confluence Space",
                    "privilege_zone": True  # Sensitive spaces = Tier 0
                }
            },
            {
                "kind_name": "CFPage",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-file-alt", "color": "#26a69a"},
                    "description": "Confluence Page or Blogpost"
                }
            },
            {
                "kind_name": "JProject",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-folder-open", "color": "#3949ab"},
                    "description": "Jira Project",
                    "privilege_zone": True  # Critical projects = Tier 0
                }
            },
            {
                "kind_name": "JIssue",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-circle-exclamation", "color": "#d32f2f"},
                    "description": "Jira Issue (ticket/bug/story)"
                }
            },
            {
                "kind_name": "JRole",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-user-shield", "color": "#fbc02d"},
                    "description": "Jira Project Role"
                }
            },
            {
                "kind_name": "JPermission",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-key", "color": "#7c4dff"},
                    "description": "Jira permission"
                }
            },
            {
                "kind_name": "JGlobalPermission",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-shield-alt", "color": "#5e35b1"},
                    "description": "Jira Global Permission",
                    "privilege_zone": True  # Global admin perms = Tier 0
                }
            },
            {
                "kind_name": "CFGlobalPermission",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-shield", "color": "#00838f"},
                    "description": "Confluence Global Permission",
                    "privilege_zone": True  # Global admin perms = Tier 0
                }
            },
            {
                "kind_name": "OrgRole",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-user-tie", "color": "#6d4c41"},
                    "description": "Organization-level role"
                }
            },
            {
                "kind_name": "JApplicationRole",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-layer-group", "color": "#546e7a"},
                    "description": "Jira Application Role"
                }
            },
            {
                "kind_name": "JServiceDesk",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-life-ring", "color": "#ff7043"},
                    "description": "Jira Service Management project"
                }
            },
            {
                "kind_name": "AtlassianInstance",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-cloud", "color": "#0052CC"},
                    "description": "Atlassian Cloud organization root"
                }
            },
            {
                "kind_name": "ConfluenceInstance",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-server", "color": "#00897b"},
                    "description": "Confluence product instance"
                }
            },
            {
                "kind_name": "JiraInstance",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-server", "color": "#0052CC"},
                    "description": "Jira product instance"
                }
            },
            {
                "kind_name": "Webhook",
                "config": {
                    "icon": {"type": "font-awesome", "name": "fa-webhook", "color": "#ff5722"},
                    "description": "Webhook endpoint (persistence/exfil risk)"
                }
            }
        ],

        # Edge types - ALL MARKED AS TRAVERSABLE for pathfinding
        "edge_kinds": [
            # Group Membership Edges
            {
                "kind_name": "CFMemberOfGroup",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE
                "cross_platform": False,
                "category": "Group Membership",
                "description": "User is a member of Atlassian group",
                "abuse_info": "Members inherit all group permissions to spaces/projects. Compromise a user in privileged group → inherit admin rights.",
                "opsec_info": "Group membership changes logged in Atlassian audit logs. Check 'User added to group' events."
            },
            {
                "kind_name": "MemberOf",  # BloodHound canonical
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": False,
                "category": "Group Membership",
                "description": "BloodHound canonical membership edge",
                "abuse_info": "Standard BloodHound group membership. Enables transitive permission inheritance.",
                "opsec_info": "Group membership audit logs."
            },
            {
                "kind_name": "CFMemberOfTeam",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": False,
                "category": "Team Membership",
                "description": "User is member of Atlassian Team",
                "abuse_info": "Team members inherit team permissions. Teams can have space/project access.",
                "opsec_info": "Team membership changes logged."
            },

            # Permission Edges (CRITICAL FOR ATTACK PATHS)
            {
                "kind_name": "CFHasPermission",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE - KEY EDGE
                "cross_platform": False,
                "category": "Confluence Permissions",
                "description": "User/group has permissions on Confluence space",
                "abuse_info": "Permissions array contains cf_create_page, cf_delete_space, cf_set_permissions, etc. cf_set_permissions = modify ACLs = privilege escalation. cf_delete_space = destruction. cf_export_space = data exfiltration.",
                "opsec_info": "Permission grants logged. Using high-risk permissions (delete, export, set_permissions) creates audit events with user, timestamp, and action details."
            },
            {
                "kind_name": "JHasProjectPermission",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE
                "cross_platform": False,
                "category": "Jira Permissions",
                "description": "User/group has permissions on Jira project",
                "abuse_info": "Permissions include ADMINISTER_PROJECTS (full project admin), BROWSE_PROJECTS (view), CREATE_ISSUES, DELETE_ISSUES. ADMINISTER_PROJECTS = full control over project configuration, users, workflows.",
                "opsec_info": "Project permission changes logged. Admin actions create detailed audit trails."
            },
            {
                "kind_name": "JHasRole",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": False,
                "category": "Jira Roles",
                "description": "User/group has Jira project role",
                "abuse_info": "Roles grant bundles of permissions. 'Administrators' role = project admin. Custom roles may have escalation paths.",
                "opsec_info": "Role assignments logged."
            },

            # Global Permission Edges (TIER 0)
            {
                "kind_name": "CFHasGlobalPermission",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE - TIER 0 PATH
                "cross_platform": False,
                "category": "Global Permissions",
                "description": "User/group has Confluence global permission",
                "abuse_info": "CRITICAL: Global permissions include CONFLUENCE_ADMIN (full instance admin), CREATE_SPACE (can create spaces), SYSTEM_ADMIN (system-level admin). CONFLUENCE_ADMIN = full control over all spaces, users, settings. SYSTEM_ADMIN = can install apps, modify system configuration.",
                "opsec_info": "Global permission use creates high-visibility audit logs. Admin console access logged separately."
            },
            {
                "kind_name": "JHasGlobalPermission",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE - TIER 0 PATH
                "cross_platform": False,
                "category": "Global Permissions",
                "description": "User/group has Jira global permission",
                "abuse_info": "CRITICAL: ADMINISTER_JIRA = full Jira instance admin. CREATE_SHARED_OBJECTS = create filters/dashboards visible to all. MANAGE_GROUP_FILTER_SUBSCRIPTIONS = access to all filter subscriptions. ADMINISTER_JIRA = install apps, modify system, access all projects.",
                "opsec_info": "Jira admin actions create detailed audit logs with full context."
            },

            # Containment Edges
            {
                "kind_name": "Contains",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE - enables hierarchical paths
                "cross_platform": False,
                "category": "Containment",
                "description": "Container contains object (Space→Page, Project→Issue)",
                "abuse_info": "Containment enables transitive access. Access to space = access to all pages. Access to project = access to all issues.",
                "opsec_info": "N/A - structural relationship"
            },
            {
                "kind_name": "CFSpaceContainsPage",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": False,
                "category": "Containment",
                "description": "Space contains page",
                "abuse_info": "Space-level permissions apply to all contained pages. Compromise space = compromise all pages.",
                "opsec_info": "N/A - structural relationship"
            },
            {
                "kind_name": "JProjectContainsIssue",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": False,
                "category": "Containment",
                "description": "Project contains issue",
                "abuse_info": "Project permissions apply to issues. BROWSE_PROJECTS on project = view all issues.",
                "opsec_info": "N/A - structural relationship"
            },

            # Cross-Platform Sync Edges (AD/Azure ↔ Atlassian)
            {
                "kind_name": "SyncedToCFUser",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE - CRITICAL for cross-platform paths
                "cross_platform": True,  # Marks as cross-platform edge
                "category": "Cross Platform",
                "description": "AD/Azure user synced to Atlassian Cloud user",
                "abuse_info": "CRITICAL: Compromising source identity (AD/Azure) grants Atlassian access. Atlassian Cloud often uses SSO/SAML from Azure AD. Compromised Azure account = Atlassian access. Check user's emailAddress property for match.",
                "opsec_info": "Initial Atlassian login from compromised account creates 'User logged in' audit event. Check for unusual login locations, times, or user agents."
            },
            {
                "kind_name": "SyncedToADUser",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": True,
                "category": "Cross Platform",
                "description": "Atlassian user synced to AD user (reverse)",
                "abuse_info": "Reverse sync path (uncommon but possible). Some orgs sync Atlassian changes back to AD.",
                "opsec_info": "Bidirectional sync is rare. Review SAML/SCIM configuration."
            },
            {
                "kind_name": "SyncedToAZUser",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": True,
                "category": "Cross Platform",
                "description": "Atlassian user synced to Azure AD user (reverse)",
                "abuse_info": "Azure → Atlassian sync via SAML/OIDC. Compromising Azure identity = Atlassian access.",
                "opsec_info": "Monitor Azure AD sign-in logs for Atlassian Cloud app access."
            },

            # Administrative Control Edges
            {
                "kind_name": "CFSpaceAdmin",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE
                "cross_platform": False,
                "category": "Administrative Rights",
                "description": "User is Space Administrator",
                "abuse_info": "Space admin can modify all space settings, permissions, and content. Can grant self additional permissions. Can delete space.",
                "opsec_info": "Space admin actions logged with full detail."
            },
            {
                "kind_name": "JProjectAdmin",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": False,
                "category": "Administrative Rights",
                "description": "User is Project Administrator",
                "abuse_info": "Project admin has ADMINISTER_PROJECTS permission. Full control over project configuration, roles, permissions, workflows.",
                "opsec_info": "Project admin actions create detailed audit logs."
            },
            {
                "kind_name": "OrgAdmin",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE - TIER 0
                "cross_platform": False,
                "category": "Administrative Rights",
                "description": "User is Organization Administrator",
                "abuse_info": "CRITICAL: Org admin has full control over entire Atlassian Cloud organization. Can manage all products, users, billing, security settings. Highest privilege level.",
                "opsec_info": "Org admin console access creates high-visibility audit logs. All admin actions logged with full context."
            },

            # Webhook Edges (Persistence/Exfiltration)
            {
                "kind_name": "CanCreateWebhook",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,  # TRAVERSABLE - lateral movement
                "cross_platform": False,
                "category": "Webhook Permissions",
                "description": "User can create webhooks",
                "abuse_info": "Webhooks enable data exfiltration and persistence. Attacker can create webhook that sends all space/project events to attacker-controlled server. Events include page changes, issue updates, user actions. Persistence: webhook survives even if user access revoked.",
                "opsec_info": "Webhook creation logged. Monitor for webhooks with external URLs or unusual event subscriptions."
            },
            {
                "kind_name": "CanModifyWebhook",
                "plugin_id": PLUGIN_ID,
                "pathfinding": True,
                "cross_platform": False,
                "category": "Webhook Permissions",
                "description": "User can modify webhooks",
                "abuse_info": "Modify existing webhooks to point to attacker server. Change event subscriptions to capture sensitive data.",
                "opsec_info": "Webhook modifications logged."
            }
        ],

        # Cross-platform mappings
        "cross_platform_mappings": [
            {
                "source_plugin": "ad",
                "target_plugin": PLUGIN_ID,
                "match_property": "userprincipalname",  # AD UPN → Atlassian email
                "forward_edge": "SyncedToCFUser",
                "reverse_edge": "SyncedToADUser",
                "enabled": True
            },
            {
                "source_plugin": "azure",
                "target_plugin": PLUGIN_ID,
                "match_property": "userprincipalname",  # Azure UPN → Atlassian email
                "forward_edge": "SyncedToCFUser",
                "reverse_edge": "SyncedToAZUser",
                "enabled": True
            },
            {
                "source_plugin": PLUGIN_ID,
                "target_plugin": "ad",
                "match_property": "emailAddress",  # Atlassian email → AD UPN
                "forward_edge": "SyncedToADUser",
                "reverse_edge": "SyncedToCFUser",
                "enabled": True
            },
            {
                "source_plugin": PLUGIN_ID,
                "target_plugin": "azure",
                "match_property": "emailAddress",  # Atlassian email → Azure UPN
                "forward_edge": "SyncedToAZUser",
                "reverse_edge": "SyncedToCFUser",
                "enabled": True
            }
        ],

        # UI tabs
        "ui_tabs": [
            # CFUser tabs
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "CFUser",
                "tab_label": "Group Membership",
                "tab_order": 1,
                "query_type": "cf-user-groups",
                "cypher_query": "MATCH (u:CFUser {objectid: $objectid})-[:CFMemberOfGroup|MemberOf]->(g:CFGroup) RETURN g"
            },
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "CFUser",
                "tab_label": "Accessible Spaces",
                "tab_order": 2,
                "query_type": "cf-user-spaces",
                "cypher_query": "MATCH (u:CFUser {objectid: $objectid})-[:CFMemberOfGroup*0..1]->(p)-[:CFHasPermission]->(s:CFSpace) RETURN DISTINCT s LIMIT 100"
            },
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "CFUser",
                "tab_label": "Jira Projects",
                "tab_order": 3,
                "query_type": "cf-user-projects",
                "cypher_query": "MATCH (u:CFUser {objectid: $objectid})-[:CFMemberOfGroup*0..1]->(p)-[:JHasProjectPermission]->(j:JProject) RETURN DISTINCT j LIMIT 100"
            },
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "CFUser",
                "tab_label": "Global Permissions",
                "tab_order": 4,
                "query_type": "cf-user-global-perms",
                "cypher_query": "MATCH (u:CFUser {objectid: $objectid})-[:CFMemberOfGroup*0..1]->(p)-[:CFHasGlobalPermission|JHasGlobalPermission]->(gp) RETURN gp"
            },
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "CFUser",
                "tab_label": "Synced Identities",
                "tab_order": 5,
                "query_type": "cf-user-synced",
                "cypher_query": "MATCH (u:CFUser {objectid: $objectid})-[:SyncedToADUser|SyncedToAZUser]-(identity) RETURN identity"
            },

            # CFSpace tabs
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "CFSpace",
                "tab_label": "Members",
                "tab_order": 1,
                "query_type": "cf-space-members",
                "cypher_query": "MATCH (p)-[:CFHasPermission]->(s:CFSpace {objectid: $objectid}) RETURN p LIMIT 100"
            },
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "CFSpace",
                "tab_label": "Pages",
                "tab_order": 2,
                "query_type": "cf-space-pages",
                "cypher_query": "MATCH (s:CFSpace {objectid: $objectid})-[:CFSpaceContainsPage]->(pg:CFPage) RETURN pg LIMIT 100"
            },
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "CFSpace",
                "tab_label": "Effective Access",
                "tab_order": 3,
                "query_type": "cf-space-effective",
                "cypher_query": "MATCH (u:CFUser)-[:CFMemberOfGroup*0..2]->(g)-[:CFHasPermission]->(s:CFSpace {objectid: $objectid}) RETURN DISTINCT u LIMIT 100"
            },

            # JProject tabs
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "JProject",
                "tab_label": "Members",
                "tab_order": 1,
                "query_type": "j-project-members",
                "cypher_query": "MATCH (p)-[:JHasProjectPermission]->(j:JProject {objectid: $objectid}) RETURN p LIMIT 100"
            },
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "JProject",
                "tab_label": "Issues",
                "tab_order": 2,
                "query_type": "j-project-issues",
                "cypher_query": "MATCH (j:JProject {objectid: $objectid})-[:JProjectContainsIssue]->(i:JIssue) RETURN i LIMIT 100"
            },
            {
                "plugin_id": PLUGIN_ID,
                "node_kind": "JProject",
                "tab_label": "Roles",
                "tab_order": 3,
                "query_type": "j-project-roles",
                "cypher_query": "MATCH (r:JRole)-[:AppliesTo]->(j:JProject {objectid: $objectid}) RETURN r"
            }
        ],

        # Pre-built queries
        "queries": [
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "All Atlassian Users",
                "category": "Discovery",
                "cypher_query": "MATCH (u:CFUser) RETURN u.displayName, u.emailAddress, u.active LIMIT 100",
                "description": "List all Atlassian Cloud users",
                "display_order": 1
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Users Synced from AD/Azure",
                "category": "Cross-Platform",
                "cypher_query": "MATCH (identity)-[:SyncedToCFUser]->(cf:CFUser) WHERE labels(identity)[0] IN ['User', 'AZUser'] RETURN identity.name, cf.displayName, cf.emailAddress LIMIT 100",
                "description": "Find AD/Azure users that sync to Atlassian",
                "display_order": 2
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Confluence Space Administrators",
                "category": "Privilege Escalation",
                "cypher_query": "MATCH (u:CFUser)-[:CFSpaceAdmin]->(s:CFSpace) RETURN u.displayName, s.name LIMIT 100",
                "description": "Users with Space Admin privileges",
                "display_order": 3
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Jira Project Administrators",
                "category": "Privilege Escalation",
                "cypher_query": "MATCH (u:CFUser)-[:JProjectAdmin]->(p:JProject) RETURN u.displayName, p.name LIMIT 100",
                "description": "Users with Project Admin privileges",
                "display_order": 4
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Organization Administrators (Tier 0)",
                "category": "Tier Zero",
                "cypher_query": "MATCH (u:CFUser)-[:OrgAdmin]->(org:AtlassianInstance) RETURN u.displayName, u.emailAddress, org.name",
                "description": "CRITICAL: Org admins have full control over Atlassian Cloud",
                "display_order": 5
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Users with Global Admin Permissions",
                "category": "Tier Zero",
                "cypher_query": "MATCH (u:CFUser)-[:CFMemberOfGroup*0..1]->(p)-[:CFHasGlobalPermission|JHasGlobalPermission]->(gp) WHERE gp.permission CONTAINS 'ADMIN' RETURN u.displayName, gp.permission LIMIT 100",
                "description": "Users with CONFLUENCE_ADMIN or ADMINISTER_JIRA permissions",
                "display_order": 6
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Shortest Path from AD to Atlassian Admin",
                "category": "Attack Paths",
                "cypher_query": "MATCH (ad:User) MATCH (cf:CFUser)-[:OrgAdmin|CFHasGlobalPermission|JHasGlobalPermission]->() MATCH p=shortestPath((ad)-[*..15]->(cf)) RETURN p LIMIT 10",
                "description": "Find attack paths from AD users to Atlassian admins",
                "display_order": 7
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Cross-Platform: Azure → Atlassian → AD",
                "category": "Attack Paths",
                "cypher_query": "MATCH p=(az:AZUser)-[:SyncedToCFUser]->(cf:CFUser)-[*1..5]->()-[:SyncedToADUser]->(ad:User) RETURN p LIMIT 10",
                "description": "Find paths from Azure through Atlassian back to AD",
                "display_order": 8
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Users Who Can Create Webhooks (Persistence)",
                "category": "Persistence",
                "cypher_query": "MATCH (u:CFUser)-[:CanCreateWebhook]->() RETURN u.displayName, u.emailAddress LIMIT 100",
                "description": "Webhook creation enables data exfiltration and persistence",
                "display_order": 9
            },
            {
                "plugin_id": PLUGIN_ID,
                "query_name": "Overprivileged Users (10+ Spaces/Projects)",
                "category": "Risk Analysis",
                "cypher_query": "MATCH (u:CFUser)-[:CFMemberOfGroup*0..2]->(g)-[:CFHasPermission|JHasProjectPermission]->(resource) WITH u, count(DISTINCT resource) as access_count WHERE access_count > 10 RETURN u.displayName, access_count ORDER BY access_count DESC LIMIT 50",
                "description": "Users with access to many spaces/projects (potential overprivilege)",
                "display_order": 10
            }
        ]
    }

    # Send registration request
    print(f"[*] Registering AtlassianHound plugin with BloodHound...")
    print(f"[*] BloodHound URL: {BLOODHOUND_URL}")
    print(f"[*] Plugin: {PLUGIN_NAME}")
    print(f"[*] Version: {PLUGIN_VERSION}")
    print()

    response = requests.post(
        f"{BLOODHOUND_URL}/api/v2/plugins",
        headers=get_auth_headers(),
        json=registration_payload
    )

    if response.status_code in [200, 201]:
        result = response.json()
        print(f"✅ Plugin registered successfully!")
        print(f"   - Nodes: {result.get('components', {}).get('nodes', 0)}")
        print(f"   - Edges: {result.get('components', {}).get('edges', 0)} (ALL TRAVERSABLE)")
        print(f"   - UI Tabs: {result.get('components', {}).get('ui_tabs', 0)}")
        print(f"   - Queries: {result.get('components', {}).get('queries', 0)}")
        print(f"   - Mappings: {result.get('components', {}).get('mappings', 0)}")
        print()
        print(f"🎯 Attack pathing enabled for Confluence + Jira!")
        print(f"   All Atlassian edges are now traversable in pathfinding.")
        print()
        print(f"✅ Privilege zones supported:")
        print(f"   - CFUser (admin users)")
        print(f"   - CFSpace (sensitive spaces)")
        print(f"   - JProject (critical projects)")
        print(f"   - Global permissions (CONFLUENCE_ADMIN, ADMINISTER_JIRA)")
        print()
        print(f"Next steps:")
        print(f"  1. Run your AtlassianHound collector: python atlassian_hound.py")
        print(f"  2. Upload output/open_graph.json to BloodHound")
        print(f"  3. Test attack paths:")
        print(f"     MATCH p=shortestPath((ad:User)-[*..10]->(cf:CFUser)-[:OrgAdmin]->())")
        print(f"     WHERE ANY(r IN relationships(p) WHERE type(r) CONTAINS 'CF')")
        print(f"     RETURN p LIMIT 10")
        print()
    else:
        print(f"❌ Registration failed: {response.status_code}")
        print(f"   Response: {response.text}")
        exit(1)

def verify_pathfinding() -> None:
    """Verify Atlassian edges are traversable."""
    print("[*] Verifying pathfinding edge registration...")

    response = requests.get(
        f"{BLOODHOUND_URL}/api/v2/custom-edge-kinds/pathfinding",
        headers=get_auth_headers()
    )

    if response.status_code == 200:
        result = response.json()
        edges = result.get("pathfinding_edges", [])
        atlassian_edges = [e for e in edges if "CF" in e or "Synced" in e or "J" in e]

        print(f"✅ Traversable Atlassian edges: {len(atlassian_edges)}")
        for edge in atlassian_edges:
            print(f"   - {edge}")
        print()
    else:
        print(f"⚠️  Could not verify: {response.status_code}")

if __name__ == "__main__":
    if not BLOODHOUND_TOKEN:
        print("❌ Error: BLOODHOUND_TOKEN environment variable not set")
        print()
        print("To get a token:")
        print("  1. Log into BloodHound CE")
        print("  2. Go to Settings → API Tokens")
        print("  3. Create token with 'write' permissions")
        print("  4. Export: export BLOODHOUND_TOKEN='your-token'")
        print()
        exit(1)

    register_plugin()
    verify_pathfinding()

    print("✅ Done! Atlassian Cloud is now a first-class BloodHound plugin.")
    print()
    print("All edges are TRAVERSABLE for automatic pathfinding:")
    print("  - CFMemberOfGroup, CFHasPermission, CFHasGlobalPermission")
    print("  - JHasProjectPermission, JHasGlobalPermission")
    print("  - SyncedToCFUser (AD/Azure → Atlassian)")
    print("  - OrgAdmin (Tier 0), CFSpaceAdmin, JProjectAdmin")
    print("  - CanCreateWebhook (persistence)")
    print()
    print("Compatible with SpecterOps design requirements:")
    print("  ✅ Directional edges (attack flow)")
    print("  ✅ Unique identifiers (objectid)")
    print("  ✅ Distinct names (CF*/J* prefixes)")
    print("  ✅ Multi-node paths")
    print("  ✅ Traversable edges (pathfinding enabled)")
    print("  ✅ Privilege zones (Tier 0 integration)")
    print("  ✅ Searchable nodes")
