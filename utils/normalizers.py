from __future__ import annotations

import re
from typing import Optional


_NON_WORD_RE = re.compile(r"[^A-Za-z0-9]+")


def _slug(value: str) -> str:
    cleaned = _NON_WORD_RE.sub("-", value.strip())
    cleaned = cleaned.strip("-")
    return cleaned.lower() or "unknown"


def canonical_user_id(account_id: str) -> str:
    return f"CFUser:{account_id}"


def canonical_group_id(group_id: Optional[str] = None, name: Optional[str] = None) -> str:
    if group_id:
        return f"CFGroup:{group_id}"
    if name:
        return f"CFGroup:{_slug(name)}"
    raise ValueError("Group identifier requires group_id or name")


def canonical_team_id(team_id: str) -> str:
    return f"CFTeam:{team_id}"


def canonical_space_id(space_id: str) -> str:
    return f"CFSpace:{space_id}"


def canonical_project_id(project_id: str) -> str:
    return f"JProject:{project_id}"


def canonical_issue_id(issue_id: str) -> str:
    return f"JIssue:{issue_id}"


def canonical_role_id(project_id: str, role_identifier: str, *, is_numeric: bool = False) -> str:
    suffix = role_identifier if is_numeric else _slug(role_identifier)
    return f"JRole:{project_id}:{suffix}"


def canonical_permission_id(permission_key: str) -> str:
    return f"JPermission:{permission_key}"


def canonical_global_permission_id(permission_key: str) -> str:
    return f"JGlobalPermission:{permission_key}"


def canonical_confluence_permission_id(permission_key: str) -> str:
    return f"CFGlobalPermission:{permission_key}"


def canonical_org_role_id(role_id: str) -> str:
    return f"OrgRole:{role_id}"


def canonical_application_role_id(role_key: str) -> str:
    return f"JApplicationRole:{role_key}"


def canonical_service_desk_id(service_desk_id: str) -> str:
    return f"JServiceDesk:{service_desk_id}"


def canonical_page_id(page_id: str) -> str:
    return f"CFPage:{page_id}"


def canonical_instance_node(product: str) -> str:
    return f"{product}Instance:Global"

def canonical_atlassian_instance_id(identifier: Optional[str] = None) -> str:
    token = (identifier or "").strip()
    if not token:
        return "AtlassianInstance:global"
    if token.startswith("http://") or token.startswith("https://"):
        token = token.split("://", 1)[-1]
    token = token.split("/", 1)[0]
    return f"AtlassianInstance:{_slug(token)}"


def user_properties(account_id: str, display_name: str, email: str = "", active: bool = True) -> dict:
    return {
        "accountId": account_id or "",
        "objectid": account_id or "",
        "displayName": display_name or "",
        "emailAddress": email or "",
        "name": display_name or account_id or "",
        "active": bool(active),
    }


def group_properties(group_id: str, name: str) -> dict:
    return {
        "groupId": group_id or "",
        "objectid": group_id or "",
        "name": name or "",
        "displayName": name or group_id or "",
    }


def team_properties(team_id: str, display_name: str, description: str, organization_id: str) -> dict:
    return {
        "teamId": team_id or "",
        "objectid": team_id or "",
        "displayName": display_name or "",
        "description": description or "",
        "organizationId": organization_id or "",
        "name": display_name or team_id or "",
    }


def space_properties(space_id: str, key: str, name: str, space_type: str) -> dict:
    return {
        "id": space_id or "",
        "objectid": space_id or "",
        "key": key or "",
        "name": name or "",
        "spaceType": space_type or "",
    }


def project_properties(project_id: str, key: str, name: str, project_type: str) -> dict:
    return {
        "id": project_id or "",
        "objectid": project_id or "",
        "key": key or "",
        "name": name or "",
        "projectType": project_type or "",
    }


def permission_properties(permission_key: str, description: str) -> dict:
    return {
        "permission": permission_key or "",
        "objectid": permission_key or "",
        "description": description or "",
    }


def role_properties(project_id: str, role_id: str, name: str) -> dict:
    return {
        "projectId": project_id or "",
        "roleId": role_id or "",
        "objectid": role_id or "",
        "name": name or "",
    }


def issue_properties(issue_id: str, key: str, summary: str) -> dict:
    return {
        "id": issue_id or "",
        "objectid": issue_id or "",
        "key": key or "",
        "summary": summary or "",
    }


def global_permission_properties(permission_key: str, description: str, scope: str) -> dict:
    return {
        "permission": permission_key or "",
        "objectid": permission_key or "",
        "description": description or "",
        "scope": scope or "",
    }


def org_role_properties(role_id: str, name: str, description: str) -> dict:
    return {
        "roleId": role_id or "",
        "objectid": role_id or "",
        "name": name or "",
        "description": description or "",
    }


def application_role_properties(
    role_key: str,
    name: str,
    default_groups: list[str],
    selected_by_default: bool,
) -> dict:
    return {
        "roleKey": role_key or "",
        "objectid": role_key or "",
        "name": name or "",
        "defaultGroups": default_groups or [],
        "selectedByDefault": bool(selected_by_default),
    }


def service_desk_properties(
    desk_id: str,
    name: str,
    project_id: str,
    project_key: str,
) -> dict:
    return {
        "serviceDeskId": desk_id or "",
        "objectid": desk_id or "",
        "name": name or "",
        "projectId": project_id or "",
        "projectKey": project_key or "",
    }


def page_properties(page_id: str, title: str, space_key: str, page_type: str) -> dict:
    return {
        "id": page_id or "",
        "objectid": page_id or "",
        "title": title or "",
        "spaceKey": space_key or "",
        "type": page_type or "",
    }


def canonical_webhook_id(webhook_id: str) -> str:
    return f"Webhook:{webhook_id}"


def canonical_app_id(app_key: str, instance_type: str = "") -> str:
    """
    Generate canonical ID for third-party apps/plugins.

    Args:
        app_key: The plugin/app key (e.g., com.example.myapp)
        instance_type: Optional instance type ("Jira" or "Confluence")

    Returns:
        Canonical app ID like "ThirdPartyApp:jira:com-example-myapp"
    """
    slug = _slug(app_key)
    if instance_type:
        return f"ThirdPartyApp:{instance_type.lower()}:{slug}"
    return f"ThirdPartyApp:{slug}"


def webhook_properties(
    webhook_id: str,
    name: str,
    url: str,
    events: list,
    enabled: bool,
    scope_type: str,
    scope_id: str,
    is_external: bool,
) -> dict:
    return {
        "webhookId": webhook_id or "",
        "objectid": webhook_id or "",
        "name": name or "",
        "url": url or "",
        "events": events or [],
        "enabled": bool(enabled),
        "scopeType": scope_type or "",
        "scopeId": scope_id or "",
        "isExternal": bool(is_external),
    }


def canonical_security_scheme_id(scheme_id: str) -> str:
    return f"JSecurityScheme:{scheme_id}"


def canonical_security_level_id(scheme_id: str, level_id: str) -> str:
    return f"JSecurityLevel:{scheme_id}:{level_id}"


def security_scheme_properties(
    scheme_id: str,
    name: str,
    description: str,
    default_level_id: str,
) -> dict:
    return {
        "schemeId": scheme_id or "",
        "objectid": scheme_id or "",
        "name": name or "",
        "description": description or "",
        "defaultLevelId": default_level_id or "",
    }


def security_level_properties(
    level_id: str,
    scheme_id: str,
    name: str,
    description: str,
    is_default: bool,
    is_high_value: bool,
) -> dict:
    return {
        "levelId": level_id or "",
        "objectid": level_id or "",
        "schemeId": scheme_id or "",
        "name": name or "",
        "description": description or "",
        "isDefault": bool(is_default),
        "isHighValue": bool(is_high_value),
    }
