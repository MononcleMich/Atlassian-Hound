from __future__ import annotations

from typing import Any, Dict, List

ATTACK_RULES: Dict[str, List[Dict[str, str]]] = {
    # Privilege Escalation edges
    "AdminTo": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},
        {"tactic": "Credential Access", "technique": "T1078"},
    ],
    "GenericWrite": [
        {"tactic": "Persistence", "technique": "T1543"},
        {"tactic": "Privilege Escalation", "technique": "T1543"},
    ],
    "CFHasPermission": [
        {"tactic": "Persistence", "technique": "T1098"},
    ],

    # Group membership edges
    "CFMemberOfGroup": [
        {"tactic": "Privilege Escalation", "technique": "T1098"},
    ],
    "CFMemberOfTeam": [
        {"tactic": "Privilege Escalation", "technique": "T1098"},
    ],
    "MemberOf": [
        {"tactic": "Privilege Escalation", "technique": "T1098"},
    ],

    # Jira role edges
    "JLeads": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Persistence", "technique": "T1098"},               # Account Manipulation
    ],
    "JRoleInProject": [
        {"tactic": "Discovery", "technique": "T1580"},                 # Cloud Infrastructure Discovery
    ],
    "JAssignedToRole": [
        {"tactic": "Privilege Escalation", "technique": "T1098"},      # Account Manipulation
    ],
    "JGroupAssignedToRole": [
        {"tactic": "Privilege Escalation", "technique": "T1098"},      # Account Manipulation
    ],

    # Permission edges
    "CFPermissionGrantedTo": [
        {"tactic": "Persistence", "technique": "T1098"},               # Account Manipulation
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
    ],
    "JCanViewIssue": [
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
    ],
    "JCanEditIssue": [
        {"tactic": "Impact", "technique": "T1565"},                    # Data Manipulation
        {"tactic": "Defense Evasion", "technique": "T1070.004"},       # File Deletion (cover tracks)
    ],
    "JCanCommentIssue": [
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
    ],
    "JHasPermission": [
        {"tactic": "Discovery", "technique": "T1069"},                 # Permission Groups Discovery
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
    ],
    "JRoleHasPermission": [
        {"tactic": "Discovery", "technique": "T1069"},                 # Permission Groups Discovery
    ],

    # Confluence permission edges
    "CFCanView": [
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
    ],
    "CFCanComment": [
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
        {"tactic": "Persistence", "technique": "T1098.001"},           # Additional Cloud Credentials (comment-based backdoors)
    ],
    "CFCanEdit": [
        {"tactic": "Impact", "technique": "T1565"},                    # Data Manipulation
        {"tactic": "Persistence", "technique": "T1098.001"},           # Additional Cloud Credentials (embed malicious links)
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
    ],
    "CFPageRestriction": [
        {"tactic": "Discovery", "technique": "T1069"},                 # Permission Groups Discovery
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
    ],

    # Team management edges
    "CFTeamOwner": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Persistence", "technique": "T1098"},               # Account Manipulation
    ],
    "CFTeamManager": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Persistence", "technique": "T1098"},               # Account Manipulation
    ],
    "CFTeamHasMember": [
        {"tactic": "Discovery", "technique": "T1069"},                 # Permission Groups Discovery
    ],

    # Organization and application role edges
    "AssignedOrgRole": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Persistence", "technique": "T1098"},               # Account Manipulation
    ],
    "HasProductAccess": [
        {"tactic": "Discovery", "technique": "T1087.004"},             # Cloud Account Discovery
        {"tactic": "Initial Access", "technique": "T1078"},            # Valid Accounts
    ],
    "HasDefaultAccess": [
        {"tactic": "Discovery", "technique": "T1087.004"},             # Cloud Account Discovery
    ],

    # Service desk edges
    "JServiceDeskAgent": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories (access to tickets)
        {"tactic": "Persistence", "technique": "T1078.004"},           # Cloud Accounts
    ],
    "BackedByProject": [
        {"tactic": "Discovery", "technique": "T1580"},                 # Cloud Infrastructure Discovery
    ],

    # Issue relationship edges
    "JInProject": [
        {"tactic": "Discovery", "technique": "T1580"},                 # Cloud Infrastructure Discovery
    ],
    "JAssignedTo": [
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
    ],
    "JReported": [
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
    ],
    "JWatched": [
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories (issue monitoring)
        {"tactic": "Reconnaissance", "technique": "T1595.002"},        # Vulnerability Scanning
    ],

    # Discovery edges
    "Contains": [
        {"tactic": "Discovery", "technique": "T1018"},                 # Remote System Discovery
        {"tactic": "Discovery", "technique": "T1580"},                 # Cloud Infrastructure Discovery
    ],
    "PageInSpace": [
        {"tactic": "Discovery", "technique": "T1580"},                 # Cloud Infrastructure Discovery
    ],
    "AppliesTo": [
        {"tactic": "Discovery", "technique": "T1580"},                 # Cloud Infrastructure Discovery
    ],

    # Lateral movement edges
    "SameUser": [
        {"tactic": "Lateral Movement", "technique": "T1078"},          # Valid Accounts
        {"tactic": "Defense Evasion", "technique": "T1550.001"},       # Application Access Token
    ],

    # Global permission edges
    "JHasGlobalPermission": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Persistence", "technique": "T1098"},               # Account Manipulation
    ],
    "CFHasGlobalPermission": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Persistence", "technique": "T1098"},               # Account Manipulation
    ],

    # Webhook management edges
    "CanManageWebhooks": [
        {"tactic": "Persistence", "technique": "T1098.001"},  # Account Manipulation: Additional Cloud Credentials
        {"tactic": "Exfiltration", "technique": "T1567"},     # Exfiltration Over Web Service
        {"tactic": "Persistence", "technique": "T1136"},      # Create Account
    ],
    "RegisteredWebhook": [
        {"tactic": "Command and Control", "technique": "T1102"},  # Web Service
        {"tactic": "Exfiltration", "technique": "T1567"},         # Exfiltration Over Web Service
    ],

    # Security scheme edges
    "JHasSecurityLevel": [
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Defense Evasion", "technique": "T1134"},           # Access Token Manipulation
        {"tactic": "Collection", "technique": "T1213"},                # Data from Information Repositories
    ],
    "CanManageSecurityScheme": [
        {"tactic": "Persistence", "technique": "T1098"},               # Account Manipulation
        {"tactic": "Privilege Escalation", "technique": "T1078"},      # Valid Accounts
        {"tactic": "Defense Evasion", "technique": "T1562.007"},       # Disable or Modify Cloud Firewall
    ],
    "JSecurityLevelInScheme": [
        {"tactic": "Discovery", "technique": "T1580"},                 # Cloud Infrastructure Discovery
    ],
}


def apply_attack_mapping(edges: List[Dict[str, Any]]) -> None:
    """
    Apply MITRE ATT&CK mappings to edges.

    BloodHound displays these in the edge details panel:
    - mitreTechniques: List of technique IDs (e.g., ["T1078", "T1098"])
    - mitreTactics: List of tactic names (e.g., ["Privilege Escalation", "Persistence"])

    We provide BOTH array and string versions:
    - Arrays: For programmatic analysis and data preservation
    - Strings (*_str): For BloodHound UI display compatibility
    """
    for edge in edges:
        edge_kind = edge.get("kind")
        if not edge_kind:
            continue

        # Get edge properties, create if not exists
        props = edge.setdefault("properties", {})

        # Skip if already mapped
        if "mitreTechniques" in props:
            continue

        mapping = ATTACK_RULES.get(edge_kind)
        if not mapping:
            continue

        # Extract unique techniques and tactics
        techniques = list({entry["technique"] for entry in mapping if "technique" in entry})
        tactics = list({entry["tactic"] for entry in mapping if "tactic" in entry})

        # Add to edge properties (BloodHound-compatible format)
        # Provide BOTH array and string versions for maximum compatibility
        if techniques:
            props["mitreTechniques"] = techniques
            props["mitreTechniques_str"] = ", ".join(techniques)  # UI-friendly
        if tactics:
            props["mitreTactics"] = tactics
            props["mitreTactics_str"] = ", ".join(tactics)  # UI-friendly
