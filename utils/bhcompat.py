from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

LOGGER = logging.getLogger("AtlassianHound.bhcompat")

ENVIRONMENT_KIND = "AtlassianInstance"
ENVIRONMENT_LABEL = "Atlassian Cloud"
ENVIRONMENT_EDGE_KIND = "Contains"

_ENV_ATTACH_KINDS: Set[str] = {
    "CFUser",
    "CFGroup",
    "CFTeam",
    "CFSpace",
    "CFPage",
    "CFGlobalPermission",
    "JProject",
    "JIssue",
    "JRole",
    "JServiceDesk",
    "JPermission",
    "JApplicationRole",
    "OrgRole",
    "ThirdPartyApp",
    "Webhook",
    "JSecurityScheme",
    "JSecurityLevel",
}

_KNOWN_ICON_MAP: Dict[str, str] = {
    "account": "user",
    "account-circle": "user",
    "account-outline": "user",
    "account-group": "users",
    "account-multiple": "users",
    "account-multiple-outline": "users",
    "account-box": "user",
    "user": "user",
    "users": "users",
    "people-group": "users",  # FA free doesn't have people-group, use users
    "book-open": "book",  # FA free has 'book' not 'book-open'
    "folder-open": "folder",  # FA free has 'folder' not 'folder-open'
    "alert-circle": "circle-exclamation",
    "shield": "shield",  # FA free has 'shield' directly
    "shield-alt": "shield",
    "shield-halved": "shield",
    "shield-half-full": "shield",
    "key": "key",
    "cloud": "cloud",
    "circle-exclamation": "circle-exclamation",
    "triangle-exclamation": "triangle-exclamation",
    "bolt": "bolt",
    "file-alt": "file",
    "file-lines": "file",
    "webhook": "link",  # FA free doesn't have share-nodes, use link
    "share-nodes": "link",
    "life-ring": "life-ring",
    "layer-group": "layer-group",
    "user-shield": "user-shield",
    "user-secret": "user-secret",
    "user-circle": "user",
    "alert-circle": "circle-exclamation",
    "book-outline": "book",
    "puzzle-piece": "puzzle-piece",
    "bug": "bug",
    "server": "server",
}


def _normalise_icon_name(icon: Optional[str]) -> str:
    if not icon:
        return "circle"
    icon_norm = icon.strip().lower()
    if icon_norm.startswith("mdi:"):
        icon_norm = icon_norm.split(":", 1)[1]
    if icon_norm.startswith("fa-"):
        icon_norm = icon_norm[3:]
    if icon_norm.startswith("fas "):
        icon_norm = icon_norm.split(" ", 1)[1]
    return _KNOWN_ICON_MAP.get(icon_norm, icon_norm or "circle")


def _normalise_color(color: Optional[str]) -> str:
    if not color:
        return "#9E9E9E"
    value = color.strip().upper()
    if not value.startswith("#"):
        value = f"#{value}"
    if len(value) == 4:
        value = "#" + "".join(ch * 2 for ch in value[1:])
    if len(value) != 7:
        return "#9E9E9E"
    return value


def build_custom_types(model: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Extract custom node type definitions from model.json for BloodHound registration.

    CRITICAL: BloodHound CE only accepts string/text fields in searchable_properties.
    This function filters out boolean, array, and other non-string property types.
    """
    visuals = model.get("visuals", {}) or {}
    custom_types: Dict[str, Dict[str, Any]] = {}

    for node_def in model.get("nodes", []) or []:
        kind = node_def.get("kind")
        if not kind:
            continue

        visual_cfg = visuals.get(kind, {})
        icon_name = visual_cfg.get("icon") or node_def.get("icon") or "circle"
        icon_name = _normalise_icon_name(icon_name)
        color = _normalise_color(visual_cfg.get("color") or node_def.get("color"))

        display_property = node_def.get("displayProperty") or "name"
        properties: Dict[str, Any] = node_def.get("properties", {}) or {}
        searchable: List[str] = []

        # Check if explicit searchable properties are declared
        declared_searchable = node_def.get("searchableProperties")
        if isinstance(declared_searchable, (list, tuple)):
            # User explicitly declared searchable properties - validate they're strings
            searchable = [str(prop) for prop in declared_searchable if isinstance(prop, str)]
        else:
            # Auto-detect: only include string/text properties from schema
            for prop_name, prop_type in properties.items():
                prop_type_str = str(prop_type).lower()
                if "string" in prop_type_str or "text" in prop_type_str:
                    searchable.append(prop_name)

        # Ensure display_property is always searchable
        if display_property and display_property not in searchable:
            searchable.append(display_property)

        # Fallback to "name" if nothing is searchable
        if not searchable:
            searchable = ["name"]

        custom_types[kind] = {
            "icon": {
                "type": "font-awesome",
                "name": icon_name,
                "color": color,
            },
            "display_property": display_property,
            "searchable_properties": sorted(set(searchable)),
        }
    return custom_types


def ensure_environment_root(graph) -> str:
    root_id = getattr(graph, "_bh_atlassian_root_id", None)
    if root_id:
        return root_id

    instance_url = getattr(graph, "instance_url", None) or ""
    org_id = getattr(graph, "org_id", None) or ""
    identifier = org_id or instance_url or "global"
    identifier = identifier.replace("https://", "").replace("http://", "").split("/")[0]
    root_id = f"{ENVIRONMENT_KIND}:{identifier or 'global'}"

    properties = Properties(
        name=ENVIRONMENT_LABEL,
        objectid=identifier or "global",
        instanceUrl=instance_url,
        orgId=org_id,
    )
    graph.add_node(Node(id=root_id, kinds=[ENVIRONMENT_KIND], properties=properties))
    setattr(graph, "_bh_atlassian_root_id", root_id)
    setattr(graph, "_bh_atlassian_linked_nodes", set())
    LOGGER.debug("Created %s root node (%s)", ENVIRONMENT_KIND, root_id)
    return root_id


def link_node_to_environment(graph, node_id: str) -> None:
    if not node_id:
        return
    root_id = ensure_environment_root(graph)
    linked: Set[str] = getattr(graph, "_bh_atlassian_linked_nodes", set())
    if node_id in linked:
        return
    graph.add_edge(
        Edge(
            start_node=root_id,
            end_node=node_id,
            kind=ENVIRONMENT_EDGE_KIND,
            properties=Properties(source="environment-runtime"),
        )
    )
    linked.add(node_id)
    setattr(graph, "_bh_atlassian_linked_nodes", linked)


def _find_node(nodes: Iterable[Dict[str, Any]], node_id: str) -> Optional[Dict[str, Any]]:
    for node in nodes:
        if node.get("id") == node_id:
            return node
    return None


def _ensure_environment_node(nodes: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], str]:
    for node in nodes:
        if node.get("kind") == ENVIRONMENT_KIND:
            props = node.setdefault("properties", {})
            props.setdefault("name", ENVIRONMENT_LABEL)
            props.setdefault("instanceUrl", "")
            props.setdefault("orgId", "")
            if "kinds" not in node or ENVIRONMENT_KIND not in node["kinds"]:
                kinds = set(node.get("kinds", []))
                kinds.add(ENVIRONMENT_KIND)
                node["kinds"] = sorted(kinds)
            return node, node["id"]

    root_id = f"{ENVIRONMENT_KIND}:global"
    root_node = {
        "id": root_id,
        "kind": ENVIRONMENT_KIND,
        "kinds": [ENVIRONMENT_KIND],
        "label": ENVIRONMENT_LABEL,
        "properties": {
            "name": ENVIRONMENT_LABEL,
            "objectid": "global",
            "instanceUrl": "",
            "orgId": "",
        },
    }
    nodes.append(root_node)
    LOGGER.debug("Added fallback %s node (export-time)", ENVIRONMENT_KIND)
    return root_node, root_id


def _ensure_contains_edge(edges: List[Dict[str, Any]], start_id: str, end_id: str) -> None:
    edge_id = f"{ENVIRONMENT_EDGE_KIND}:{start_id}->{end_id}"
    for edge in edges:
        if edge.get("id") == edge_id or (
            edge.get("kind") == ENVIRONMENT_EDGE_KIND
            and edge.get("start", {}).get("value") == start_id
            and edge.get("end", {}).get("value") == end_id
        ):
            return
    edges.append(
        {
            "id": edge_id,
            "kind": ENVIRONMENT_EDGE_KIND,
            "kinds": [ENVIRONMENT_EDGE_KIND],
            "start": {"value": start_id, "match_by": "id"},
            "end": {"value": end_id, "match_by": "id"},
            "properties": {"source": "environment-export"},
        }
    )


def _rename_owns_edges(edges: List[Dict[str, Any]]) -> None:
    for edge in edges:
        kind = edge.get("kind")
        if kind == "Owns":
            edge["kind"] = ENVIRONMENT_EDGE_KIND
            kinds = set(edge.get("kinds", []))
            kinds.discard("Owns")
            kinds.add(ENVIRONMENT_EDGE_KIND)
            edge["kinds"] = sorted(kinds)
            props = edge.setdefault("properties", {})
            props.setdefault("source", "compatibility")


def ensure_bloodhound_compatibility(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    metadata: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    _rename_owns_edges(edges)
    root_node, root_id = _ensure_environment_node(nodes)

    environment_targets = {
        node["id"]
        for node in nodes
        if node.get("kind") in _ENV_ATTACH_KINDS
    }

    for target_id in environment_targets:
        _ensure_contains_edge(edges, root_id, target_id)

    if metadata is None:
        metadata = {}
    metadata.setdefault("source_kind", "AtlassianCloud")
    return nodes, edges, metadata


def append_threat_analysis(metadata: Dict[str, Any]) -> None:
    if "threat_analysis" in metadata:
        return
    metadata["threat_analysis"] = {
        "summary": "Atlassian cloud data ingested via AtlassianHound collector.",
        "confidence": "medium",
        "notes": [
            "Privilege analytics derived from Atlassian user, group, project, and space relationships.",
        ],
    }

