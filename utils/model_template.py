from __future__ import annotations

import json
from typing import Any, Dict

MODEL_TEMPLATE: Dict[str, Any] = json.loads(r'''{
  "description": "AtlassianHound OpenGraph model for BloodHound CE. Defines Atlassian Cloud nodes, edges, and supporting metadata.",
  "nodes": [
    {
      "kind": "CFUser",
      "label": "Atlassian Cloud User",
      "icon": "user",
      "color": "#1976d2",
      "displayProperty": "displayName",
      "properties": {
        "objectid": "string",
        "accountId": "string",
        "displayName": "string",
        "emailAddress": "string",
        "name": "string",
        "active": "boolean"
      }
    },
    {
      "kind": "CFGroup",
      "label": "Atlassian Group",
      "icon": "users",
      "color": "#8e24aa",
      "displayProperty": "displayName",
      "properties": {
        "objectid": "string",
        "groupId": "string",
        "name": "string",
        "displayName": "string"
      }
    },
    {
      "kind": "CFTeam",
      "label": "Atlassian Team",
      "icon": "people-group",
      "color": "#00897b",
      "displayProperty": "displayName",
      "properties": {
        "objectid": "string",
        "teamId": "string",
        "displayName": "string",
        "description": "string",
        "organizationId": "string",
        "name": "string"
      }
    },
    {
      "kind": "CFSpace",
      "label": "Confluence Space",
      "icon": "book-open",
      "color": "#ffb300",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "id": "string",
        "key": "string",
        "name": "string",
        "spaceType": "string"
      }
    },
    {
      "kind": "JProject",
      "label": "Jira Project",
      "icon": "folder-open",
      "color": "#3949ab",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "id": "string",
        "key": "string",
        "name": "string",
        "projectType": "string"
      }
    },
    {
      "kind": "JIssue",
      "label": "Jira Issue",
      "icon": "circle-exclamation",
      "color": "#d32f2f",
      "displayProperty": "key",
      "properties": {
        "objectid": "string",
        "id": "string",
        "key": "string",
        "summary": "string"
      }
    },
    {
      "kind": "AtlassianInstance",
      "label": "Atlassian Cloud Instance",
      "icon": "cloud",
      "color": "#0052CC",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "name": "string",
        "instanceUrl": "string",
        "orgId": "string"
      }
    },
    {
      "kind": "JRole",
      "label": "Jira Project Role",
      "icon": "user-shield",
      "color": "#fbc02d",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "projectId": "string",
        "roleId": "string",
        "name": "string"
      }
    },
    {
      "kind": "JPermission",
      "label": "Jira Permission",
      "icon": "key",
      "color": "#7c4dff",
      "displayProperty": "permission",
      "properties": {
        "objectid": "string",
        "permission": "string",
        "description": "string"
      }
    },
    {
      "kind": "JGlobalPermission",
      "label": "Jira Global Permission",
      "icon": "shield-alt",
      "color": "#5e35b1",
      "displayProperty": "permission",
      "properties": {
        "objectid": "string",
        "permission": "string",
        "description": "string",
        "scope": "string"
      }
    },
    {
      "kind": "CFGlobalPermission",
      "label": "Confluence Global Permission",
      "icon": "shield",
      "color": "#00838f",
      "displayProperty": "permission",
      "properties": {
        "objectid": "string",
        "permission": "string",
        "description": "string",
        "scope": "string"
      }
    },
    {
      "kind": "OrgRole",
      "label": "Organization Role",
      "icon": "user-tie",
      "color": "#6d4c41",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "roleId": "string",
        "name": "string",
        "description": "string"
      }
    },
    {
      "kind": "JApplicationRole",
      "label": "Jira Application Role",
      "icon": "layer-group",
      "color": "#546e7a",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "roleKey": "string",
        "name": "string",
        "defaultGroups": "string[]",
        "selectedByDefault": "boolean"
      }
    },
    {
      "kind": "JServiceDesk",
      "label": "Jira Service Desk",
      "icon": "life-ring",
      "color": "#ff7043",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "serviceDeskId": "string",
        "name": "string",
        "projectId": "string",
        "projectKey": "string"
      }
    },
    {
      "kind": "CFPage",
      "label": "Confluence Page",
      "icon": "file-alt",
      "color": "#26a69a",
      "displayProperty": "title",
      "properties": {
        "objectid": "string",
        "id": "string",
        "title": "string",
        "spaceKey": "string",
        "type": "string"
      }
    },
    {
      "kind": "JiraInstance",
      "label": "Jira Instance",
      "icon": "server",
      "color": "#0052CC",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "name": "string",
        "url": "string"
      }
    },
    {
      "kind": "ConfluenceInstance",
      "label": "Confluence Instance",
      "icon": "server",
      "color": "#00897b",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "name": "string"
      }
    },
    {
      "kind": "Webhook",
      "label": "Webhook",
      "icon": "webhook",
      "color": "#ff5722",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "webhookId": "string",
        "name": "string",
        "url": "string",
        "events": "string[]",
        "enabled": "boolean",
        "scopeType": "string",
        "scopeId": "string",
        "isExternal": "boolean"
      }
    },
    {
      "kind": "JSecurityScheme",
      "label": "Jira Security Scheme",
      "icon": "shield",
      "color": "#e91e63",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "schemeId": "string",
        "name": "string",
        "description": "string",
        "defaultLevelId": "string"
      }
    },
    {
      "kind": "JSecurityLevel",
      "label": "Jira Security Level",
      "icon": "shield-alt",
      "color": "#f44336",
      "displayProperty": "name",
      "properties": {
        "objectid": "string",
        "levelId": "string",
        "schemeId": "string",
        "name": "string",
        "description": "string",
        "isDefault": "boolean",
        "isHighValue": "boolean"
      }
    }
  ],
  "edges": [
    {
      "name": "CFMemberOfGroup",
      "label": "Member of Group",
      "direction": "out",
      "properties": {
        "direct": "boolean",
        "inherited": "boolean"
      }
    },
    {
      "name": "CFGroupHasMember",
      "label": "Group Has Member",
      "direction": "out",
      "properties": {
        "direct": "boolean",
        "inherited": "boolean"
      }
    },
    {
      "name": "MemberOf",
      "label": "MemberOf (BloodHound)",
      "direction": "out",
      "properties": {
        "direct": "boolean",
        "inherited": "boolean"
      }
    },
    {
      "name": "MemberOfReverse",
      "label": "MemberOf Reverse (BloodHound)",
      "direction": "out",
      "properties": {
        "source": "string",
        "from": "string"
      }
    },
    {
      "name": "GroupHasMember",
      "label": "GroupHasMember (BloodHound)",
      "direction": "out",
      "properties": {
        "direct": "boolean",
        "inherited": "boolean"
      }
    },
    {
      "name": "CFMemberOfTeam",
      "label": "Member of Team",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "CFTeamHasMember",
      "label": "Team Has Member",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "AppliesTo",
      "label": "Applies To",
      "direction": "out",
      "properties": {
        "scope": "string"
      }
    },
    {
      "name": "CFHasPermission",
      "label": "Has Cloud Permission",
      "direction": "out",
      "properties": {
        "permissions": "string[]",
        "inherited": "boolean"
      }
    },
    {
      "name": "CFPermissionGrantedTo",
      "label": "Permission Granted To",
      "direction": "out",
      "properties": {
        "permissions": "string[]",
        "inherited": "boolean"
      }
    },
    {
      "name": "JHasGlobalPermission",
      "label": "Has Jira Global Permission",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "CFHasGlobalPermission",
      "label": "Has Confluence Global Permission",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "AdminTo",
      "label": "AdminTo",
      "direction": "out",
      "properties": {
        "inherited": "boolean"
      }
    },
    {
      "name": "GenericWrite",
      "label": "GenericWrite",
      "direction": "out",
      "properties": {
        "inherited": "boolean"
      }
    },
    {
      "name": "JLeads",
      "label": "Leads Project",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JRoleInProject",
      "label": "Role In Project",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JAssignedToRole",
      "label": "Assigned To Role",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JGroupAssignedToRole",
      "label": "Group Assigned To Role",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "AssignedOrgRole",
      "label": "Assigned Organization Role",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JHasPermission",
      "label": "Has Jira Permission",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JRoleHasPermission",
      "label": "Role Has Permission",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "HasProductAccess",
      "label": "Has Product Access",
      "direction": "out",
      "properties": {
        "source": "string"
      }
    },
    {
      "name": "HasDefaultAccess",
      "label": "Has Default Access",
      "direction": "out",
      "properties": {
        "source": "string"
      }
    },
    {
      "name": "JInProject",
      "label": "Issue In Project",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JAssignedTo",
      "label": "Issue Assigned To",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JReported",
      "label": "Issue Reported By",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "Contains",
      "label": "Contains",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "BackedByProject",
      "label": "Service Desk Backed By Project",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JServiceDeskAgent",
      "label": "Service Desk Agent",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "PageInSpace",
      "label": "Page In Space",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "CFPageRestriction",
      "label": "Page Restriction",
      "direction": "out",
      "properties": {
        "permission": "string"
      }
    },
    {
      "name": "CFTeamOwner",
      "label": "Team Owner",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "CFTeamManager",
      "label": "Team Manager",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "SameUser",
      "label": "Same User Link",
      "direction": "bidirectional",
      "properties": {
        "email": "string"
      }
    },
    {
      "name": "JWatched",
      "label": "Watches Issue",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "CanManageWebhooks",
      "label": "Can Manage Webhooks",
      "direction": "out",
      "properties": {
        "permission": "string",
        "high_value": "boolean",
        "description": "string"
      }
    },
    {
      "name": "RegisteredWebhook",
      "label": "Registered Webhook",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "JHasSecurityLevel",
      "label": "Has Security Level Access",
      "direction": "out",
      "properties": {
        "level_name": "string",
        "inherited": "boolean",
        "via_group": "string",
        "description": "string"
      }
    },
    {
      "name": "JSecurityLevelInScheme",
      "label": "Security Level In Scheme",
      "direction": "out",
      "properties": {}
    },
    {
      "name": "CanManageSecurityScheme",
      "label": "Can Manage Security Scheme",
      "direction": "out",
      "properties": {
        "permission": "string",
        "high_value": "boolean",
        "description": "string"
      }
    }
  ],
  "mirrors": {
    "reverse_edges": {
      "MemberOf": true
    },
    "CFHasPermission": [
      {
        "edge": "AdminTo",
        "match": [
          "administer",
          "admin",
          "manage"
        ]
      },
      {
        "edge": "GenericWrite",
        "match": [
          "edit",
          "write",
          "update"
        ]
      }
    ]
  },
  "post_ingest_cypher": {
    "mirror_edges": [],
    "set_high_value": []
  },
  "visuals": {
    "CFUser": {
      "icon": "mdi:account",
      "color": "#1E88E5"
    },
    "CFGroup": {
      "icon": "mdi:account-group",
      "color": "#8E24AA"
    },
    "CFTeam": {
      "icon": "mdi:account-multiple",
      "color": "#00897B"
    },
    "CFSpace": {
      "icon": "mdi:book-open",
      "color": "#FFB300"
    },
    "JProject": {
      "icon": "mdi:folder-open",
      "color": "#3949AB"
    },
    "JIssue": {
      "icon": "mdi:alert-circle",
      "color": "#D32F2F"
    },
    "AtlassianInstance": {
      "icon": "mdi:cloud",
      "color": "#0052CC"
    }
  },
  "saved_queries": [
    {
      "name": "All Atlassian Admins",
      "description": "Users or groups with AdminTo on any Jira or Confluence asset.",
      "cypher": "MATCH (p)-[:AdminTo]->(r) RETURN p.name AS Principal, r.name AS Resource ORDER BY p.name",
      "category": "Atlassian"
    },
    {
      "name": "Users with Write/Edit Privileges",
      "description": "Principals with GenericWrite on any Atlassian resource.",
      "cypher": "MATCH (p)-[:GenericWrite]->(r) RETURN p.name AS Principal, r.name AS Editable ORDER BY p.name",
      "category": "Atlassian"
    },
    {
      "name": "Service Accounts Detected",
      "description": "Accounts flagged as service accounts.",
      "cypher": "MATCH (u:CFUser {service_account:true}) RETURN u.name, u.emailAddress",
      "category": "Atlassian"
    },
    {
      "name": "High-Value Users",
      "description": "Users marked as high_value=true.",
      "cypher": "MATCH (u:CFUser {high_value:true}) RETURN u.name, u.emailAddress",
      "category": "Atlassian"
    },
    {
      "name": "Jira Project Owners",
      "description": "Who owns or administers Jira projects.",
      "cypher": "MATCH (u:CFUser)-[:Owns|AdminTo]->(p:JProject) RETURN u.name, p.name",
      "category": "Atlassian"
    },
    {
      "name": "Group to Project Privilege Map",
      "description": "Groups and their privileges on Jira projects.",
      "cypher": "MATCH (g:CFGroup)-[r:AdminTo|GenericWrite]->(p:JProject) RETURN g.name, type(r) AS Relation, p.name",
      "category": "Atlassian"
    },
    {
      "name": "Confluence Space Admins",
      "description": "Groups or users with AdminTo on Confluence Spaces.",
      "cypher": "MATCH (n)-[:AdminTo]->(s:CFSpace) RETURN n.name, s.name",
      "category": "Atlassian"
    },
    {
      "name": "Direct Memberships",
      "description": "CFUser → CFGroup memberships.",
      "cypher": "MATCH (u:CFUser)-[:MemberOf]->(g:CFGroup) RETURN u.name, g.name",
      "category": "Atlassian"
    },
    {
      "name": "Nested Team Membership",
      "description": "CFUser → CFTeam recursive memberships.",
      "cypher": "MATCH p=(u:CFUser)-[:MemberOf*1..]->(t:CFTeam) RETURN p",
      "category": "Atlassian"
    },
    {
      "name": "Potential Escalation Paths (Atlassian → AD)",
      "description": "Paths from Atlassian to AD Users via SameUser edges.",
      "cypher": "MATCH p=(a:CFUser)-[:SameUser*1..2]->(u:User) RETURN p",
      "category": "Atlassian"
    },
    {
      "name": "🚨 External Webhook Exfiltration Channels",
      "description": "Find external webhooks that could be used for data exfiltration.",
      "cypher": "MATCH (u:CFUser)-[:CanManageWebhooks]->(ji:JiraInstance)<-[:RegisteredWebhook]-(w:Webhook) WHERE w.isExternal = true RETURN u.displayName AS User, u.emailAddress AS Email, w.name AS Webhook, w.url AS ExternalURL, w.events AS MonitoredEvents ORDER BY u.displayName",
      "category": "Offensive Security"
    },
    {
      "name": "🔒 Users with Confidential Security Level Access",
      "description": "Find users who can access high-value security levels (confidential, executive, restricted).",
      "cypher": "MATCH (u:CFUser)-[r:JHasSecurityLevel]->(sl:JSecurityLevel) WHERE sl.isHighValue = true RETURN u.displayName AS User, u.emailAddress AS Email, sl.name AS SecurityLevel, sl.description AS Description, r.inherited AS InheritedAccess, r.via_group AS ViaGroup ORDER BY sl.name, u.displayName",
      "category": "Offensive Security"
    },
    {
      "name": "🎯 Shadow Admins via Group Membership",
      "description": "Find users with AdminTo privileges inherited through group membership (often overlooked).",
      "cypher": "MATCH (u:CFUser)-[:MemberOf*1..]->(g:CFGroup)-[:AdminTo]->(p) WHERE NOT (u)-[:AdminTo]->(p) RETURN u.displayName AS ShadowAdmin, u.emailAddress AS Email, g.name AS ViaGroup, labels(p)[0] AS ResourceType, p.name AS Resource ORDER BY u.displayName",
      "category": "Offensive Security"
    },
    {
      "name": "🕵️ Service Desk Agents with Broad Access",
      "description": "Service desk agents often have access to sensitive tickets and customer data.",
      "cypher": "MATCH (u:CFUser)-[:JServiceDeskAgent]->(sd:JServiceDesk)-[:BackedByProject]->(p:JProject) RETURN u.displayName AS Agent, u.emailAddress AS Email, sd.name AS ServiceDesk, p.name AS Project, p.key AS ProjectKey ORDER BY u.displayName",
      "category": "Offensive Security"
    },
    {
      "name": "👥 Webhook Managers (Persistence Targets)",
      "description": "Users who can create webhooks are high-value targets for establishing persistence.",
      "cypher": "MATCH (u:CFUser)-[:CanManageWebhooks]->(ji:JiraInstance) RETURN u.displayName AS User, u.emailAddress AS Email, u.accountId AS AccountID, u.high_value AS IsHighValue ORDER BY u.high_value DESC, u.displayName",
      "category": "Offensive Security"
    },
    {
      "name": "🔐 Security Scheme Managers (Privilege Escalation)",
      "description": "Users who can manage security schemes can grant themselves access to any security level.",
      "cypher": "MATCH (u:CFUser)-[:CanManageSecurityScheme]->(ss:JSecurityScheme) RETURN u.displayName AS User, u.emailAddress AS Email, ss.name AS SecurityScheme, ss.description AS Description ORDER BY u.displayName",
      "category": "Offensive Security"
    },
    {
      "name": "📊 Confluence Pages with Restricted Access",
      "description": "Find restricted Confluence pages and who can access them (potential sensitive data).",
      "cypher": "MATCH (u:CFUser)-[r:CFPageRestriction]->(p:CFPage)-[:PageInSpace]->(s:CFSpace) RETURN u.displayName AS User, s.name AS Space, p.title AS Page, r.permission AS Permission ORDER BY s.name, p.title",
      "category": "Offensive Security"
    },
    {
      "name": "🎭 Cross-Product Privilege Escalation Paths",
      "description": "Find paths from low-privilege Confluence users to high-privilege Jira resources via group membership.",
      "cypher": "MATCH path = (u:CFUser)-[:MemberOf*1..3]->(g:CFGroup)-[:AdminTo]->(p:JProject) WHERE NOT (u)-[:AdminTo]->(:JProject) RETURN u.displayName AS User, [node in nodes(path) | coalesce(node.name, node.displayName)] AS EscalationPath, p.name AS TargetProject LIMIT 25",
      "category": "Offensive Security"
    },
    {
      "name": "🔍 Issue Watchers (Reconnaissance Targets)",
      "description": "Users watching issues can be targeted for phishing or social engineering (they're engaged with the topic).",
      "cypher": "MATCH (u:CFUser)-[:JWatched]->(i:JIssue)-[:JInProject]->(p:JProject) RETURN u.displayName AS Watcher, u.emailAddress AS Email, i.key AS Issue, i.summary AS Summary, p.name AS Project ORDER BY u.displayName LIMIT 50",
      "category": "Offensive Security"
    },
    {
      "name": "🌐 Team Owners (Organizational Intelligence)",
      "description": "Team owners control membership and can be targeted for organizational reconnaissance.",
      "cypher": "MATCH (u:CFUser)-[:CFTeamOwner]->(t:CFTeam) RETURN u.displayName AS Owner, u.emailAddress AS Email, t.displayName AS Team, t.organizationId AS OrgID ORDER BY u.displayName",
      "category": "Offensive Security"
    }
  ],
  "environment": {
    "root_kind": "AtlassianInstance",
    "name_property": "name"
  }
}
''')

