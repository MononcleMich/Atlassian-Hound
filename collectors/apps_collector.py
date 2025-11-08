import logging
from typing import Dict

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

from utils.common import SITE_BASE, get_auth
from utils.environment import link_node_to_environment
from utils.http import get_session, handle_http_error
from utils.normalizers import canonical_app_id, canonical_instance_node


LOG = logging.getLogger("AtlassianHound.apps")


def run(graph) -> None:
    """
    Collect information about installed third-party apps and integrations.

    Note: This collector attempts to retrieve Connect apps via UPM REST API.
    Forge apps are not accessible via public REST API on Cloud instances as of 2025.

    Data collected:
    - Connect apps (via /rest/plugins/1.0/)
    - App properties: name, key, version, vendor, enabled status, user count
    - Links to Jira/Confluence instances
    """
    LOG.info("Starting apps collector (Connect apps via UPM API)...")

    # Try to collect from both Jira and Confluence
    _collect_jira_apps(graph)
    _collect_confluence_apps(graph)

    LOG.info("Apps collector completed.")


def _collect_jira_apps(graph) -> None:
    """Collect installed Connect apps from Jira instance via UPM API."""
    auth = get_auth()
    session = get_session()

    # UPM REST API endpoint - works for Connect apps on Cloud
    url = f"{SITE_BASE}/rest/plugins/1.0/"

    try:
        resp = session.get(url, auth=auth)
        if not resp.ok:
            if handle_http_error(resp, "Jira UPM API"):
                # Retry after rate limit
                resp = session.get(url, auth=auth)
                if not resp.ok:
                    LOG.warning("Jira UPM API unavailable after retry. Skipping Jira apps collection.")
                    return
            else:
                LOG.info("Jira UPM API not accessible (may require Data Center/Server). Skipping Jira apps.")
                return
    except Exception as exc:
        LOG.error("Failed to fetch Jira apps via UPM API: %s", exc)
        return

    try:
        data = resp.json()
    except ValueError as exc:
        LOG.error("Failed to parse Jira UPM API response: %s", exc)
        return

    # Ensure Jira instance node exists
    jira_instance = canonical_instance_node("Jira")
    if jira_instance not in getattr(graph, "nodes", {}):
        graph.add_node(Node(
            id=jira_instance,
            kinds=["JiraInstance"],
            properties=Properties(name="Jira Cloud Instance", objectid=jira_instance)
        ))
    link_node_to_environment(graph, jira_instance)

    # Parse plugins/apps from UPM response
    plugins = data.get("plugins", [])
    if not plugins:
        LOG.info("No plugins found in Jira UPM API response.")
        return

    LOG.info("Found %d plugins/apps in Jira UPM response.", len(plugins))

    for plugin in plugins:
        _process_app(graph, plugin, jira_instance, "Jira")


def _collect_confluence_apps(graph) -> None:
    """Collect installed Connect apps from Confluence instance via UPM API."""
    # Atlassian Cloud shares the same domain for Jira and Confluence
    # Apps are managed at the instance level, so they're already collected from Jira
    LOG.debug("Skipping separate Confluence apps collection (shared Atlassian Cloud instance).")
    return

    auth = get_auth()
    session = get_session()

    url = f"{CONFLUENCE_SITE_BASE}/rest/plugins/1.0/"

    try:
        resp = session.get(url, auth=auth)
        if not resp.ok:
            if handle_http_error(resp, "Confluence UPM API"):
                resp = session.get(url, auth=auth)
                if not resp.ok:
                    LOG.warning("Confluence UPM API unavailable after retry. Skipping Confluence apps.")
                    return
            else:
                LOG.info("Confluence UPM API not accessible. Skipping Confluence apps.")
                return
    except Exception as exc:
        LOG.error("Failed to fetch Confluence apps via UPM API: %s", exc)
        return

    try:
        data = resp.json()
    except ValueError as exc:
        LOG.error("Failed to parse Confluence UPM API response: %s", exc)
        return

    # Ensure Confluence instance node exists
    cf_instance = canonical_instance_node("Confluence")
    if cf_instance not in getattr(graph, "nodes", {}):
        graph.add_node(Node(
            id=cf_instance,
            kinds=["ConfluenceInstance"],
            properties=Properties(name="Confluence Cloud Instance", objectid=cf_instance)
        ))
    link_node_to_environment(graph, cf_instance)

    plugins = data.get("plugins", [])
    if not plugins:
        LOG.info("No plugins found in Confluence UPM API response.")
        return

    LOG.info("Found %d plugins/apps in Confluence UPM response.", len(plugins))

    for plugin in plugins:
        _process_app(graph, plugin, cf_instance, "Confluence")


def _process_app(graph, plugin: Dict, instance_node: str, instance_type: str) -> None:
    """
    Process a single app/plugin from UPM API response and add to graph.

    Args:
        graph: The graph object to add nodes and edges to
        plugin: Plugin data from UPM API
        instance_node: ID of the Jira/Confluence instance node
        instance_type: "Jira" or "Confluence"
    """
    plugin_key = plugin.get("key")
    if not plugin_key:
        return

    # Skip Atlassian system plugins (focus on third-party apps)
    if plugin_key.startswith(("com.atlassian.jira.", "com.atlassian.confluence.",
                              "com.atlassian.plugins.", "com.atlassian.sal.",
                              "com.atlassian.streams.", "com.atlassian.gadgets.")):
        return

    app_id = canonical_app_id(plugin_key, instance_type)

    # Extract app properties
    app_name = plugin.get("name", plugin_key)
    enabled = plugin.get("enabled", False)
    user_installed = plugin.get("userInstalled", False)
    version = plugin.get("version", "unknown")

    # Vendor information
    vendor_name = "Unknown"
    vendor_url = ""
    links = plugin.get("links", {})
    if isinstance(links, dict):
        vendor_url = links.get("marketplace", "")

    # Try to get vendor from plugin modules or description
    if "vendor" in plugin:
        vendor_info = plugin["vendor"]
        if isinstance(vendor_info, dict):
            vendor_name = vendor_info.get("name", vendor_name)
            vendor_url = vendor_info.get("url", vendor_url) or vendor_info.get("link", vendor_url)
        elif isinstance(vendor_info, str):
            vendor_name = vendor_info

    # Build properties
    props = {
        "objectid": app_id,
        "name": app_name,
        "app_key": plugin_key,
        "version": version,
        "enabled": enabled,
        "user_installed": user_installed,
        "vendor": vendor_name,
        "instance_type": instance_type,
    }

    if vendor_url:
        props["vendor_url"] = vendor_url

    # Optional properties
    if "description" in plugin:
        props["description"] = plugin["description"][:500]  # Truncate long descriptions

    # Add license information if available
    if "license" in plugin:
        license_info = plugin["license"]
        if isinstance(license_info, dict):
            props["license_type"] = license_info.get("type", "unknown")
            if "valid" in license_info:
                props["license_valid"] = license_info["valid"]

    # Add user count if available (number of users with access)
    if "usersCount" in plugin:
        props["users_count"] = plugin["usersCount"]

    # Create app node
    graph.add_node(Node(
        id=app_id,
        kinds=["ThirdPartyApp"],
        properties=Properties(**props)
    ))
    link_node_to_environment(graph, app_id)

    # Link app to instance
    graph.add_edge(Edge(
        app_id,
        instance_node,
        "InstalledOn",
        Properties(enabled=enabled, version=version)
    ))

    LOG.debug("Added third-party app: %s (key=%s, enabled=%s)", app_name, plugin_key, enabled)
