import json
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = "1.0.0"


def uid(kind, raw):
    kind_map = {
        "cfuser": "CFUser",
        "cfgroup": "CFGroup",
        "cfteam": "CFTeam",
        "cfspace": "CFSpace",
        "jproject": "JProject",
        "jissue": "JIssue",
        "jrole": "JRole",
    }
    k = kind_map.get(str(kind).lower(), str(kind))
    return f"{k}:{str(raw)}"


def write_opengraph(nodes: Iterable[Dict[str, Any]],
                    edges: Iterable[Dict[str, Any]],
                    path: str) -> None:
    """Write OpenGraph single-file: {"graph":{"nodes":[...], "edges":[...]}}"""
    graph = {"graph": {"nodes": list(nodes), "edges": list(edges)}}
    Path(path).write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")

import logging


def _create_canonical_edges(edges: List[Dict[str, Any]], nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Create canonical BloodHound edges for UI compatibility.

    BloodHound CE v8.2 only recognizes built-in AD edge types like:
    - MemberOf (for group membership)
    - AdminTo (for admin control)
    - GenericAll, GenericWrite (for permissions)

    This function creates "shadow" edges with canonical names alongside our custom edges,
    so BloodHound UI can display relationships in side panels and enable pathfinding.
    """
    canonical_edges = []

    # Build node kind lookup
    node_kinds = {}
    for node in nodes:
        node_kinds[node['id']] = set(node.get('kinds', []))

    for edge in edges:
        edge_kind = edge.get('kind', '')
        start_id = edge['start']['value']
        end_id = edge['end']['value']
        props = edge.get('properties', {})

        # Skip if nodes don't exist
        if start_id not in node_kinds or end_id not in node_kinds:
            continue

        canonical_kind = None
        canonical_props = {}

        # Map: CFGroupHasMember / CFMemberOfGroup → MemberOf
        if edge_kind in ('CFGroupHasMember', 'CFMemberOfGroup', 'CFMemberOfTeam'):
            canonical_kind = 'MemberOf'
            canonical_props = {
                'isacl': False,
                'source': f'atlassianhound_{edge_kind.lower()}'
            }
            # Preserve direct/inherited property
            if 'direct' in props:
                canonical_props['direct'] = props['direct']
            if 'inherited' in props:
                canonical_props['inherited'] = props['inherited']

        # Map: CFHasPermission with admin perms → AdminTo
        elif edge_kind == 'CFHasPermission':
            perms = props.get('permissions', [])
            if isinstance(perms, str):
                perms = [perms]

            # Check for admin permissions
            admin_perms = [p for p in perms if isinstance(p, str) and ('administer' in p.lower() or 'admin' in p.lower())]

            if admin_perms:
                canonical_kind = 'AdminTo'
                canonical_props = {
                    'isacl': False,
                    'source': 'atlassianhound_cfhaspermission',
                    'permissions': ', '.join(admin_perms)  # Convert array to string for edge
                }
            elif any('write' in str(p).lower() or 'create' in str(p).lower() or 'edit' in str(p).lower() for p in perms):
                canonical_kind = 'GenericWrite'
                canonical_props = {
                    'isacl': False,
                    'source': 'atlassianhound_cfhaspermission',
                    'permissions': ', '.join([str(p) for p in perms[:5]])  # First 5 perms
                }

        # Map: JAssignedToRole → AdminTo (for Jira roles)
        elif edge_kind == 'JAssignedToRole':
            canonical_kind = 'AdminTo'
            canonical_props = {
                'isacl': False,
                'source': 'atlassianhound_jassignedtorole'
            }

        # Map: AdminTo (mirrored) → keep as-is but ensure proper format
        elif edge_kind == 'AdminTo':
            # Already canonical, but add source if not present
            if 'source' not in props:
                canonical_kind = 'AdminTo'
                canonical_props = dict(props)
                canonical_props['source'] = canonical_props.get('from', 'atlassianhound_mirror')

        # Create canonical edge if we have a mapping
        if canonical_kind:
            canonical_edge = {
                'id': f"{canonical_kind}:{start_id}->{end_id}",
                'kind': canonical_kind,
                'kinds': [canonical_kind],
                'start': {'value': start_id, 'match_by': 'id'},
                'end': {'value': end_id, 'match_by': 'id'},
                'properties': canonical_props
            }

            # Copy MITRE ATT&CK data if present
            if 'mitreTechniques' in props:
                canonical_edge['properties']['mitreTechniques'] = props['mitreTechniques']
            if 'mitreTactics' in props:
                canonical_edge['properties']['mitreTactics'] = props['mitreTactics']

            canonical_edges.append(canonical_edge)

    return canonical_edges


def export_graph(
    graph,
    filename: Optional[str] = None,
    mirror_bh_edges: bool = False,
    collector_errors: Optional[List[str]] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Export the graph to OpenGraph JSON format (BloodHound CE schema).
    - Ensures strict schema compliance (minimal required fields)
    - Deduplicates and sorts nodes/edges for deterministic output.
    - Validates all required fields and logs errors.
    - Optionally mirrors BloodHound-native edges for CE UI compatibility.
    """
    # --- Collect and sanitize nodes ---
    nodes = []
    for node_obj in getattr(graph, 'nodes', {}).values():
        if not hasattr(node_obj, 'to_dict'):
            continue
        node_data = node_obj.to_dict()
        node_data['high_value'] = getattr(node_obj, 'high_value', node_data.get('high_value', False))
        nodes.append(node_data)
    seen_node_ids = set()
    clean_nodes = []
    for node in nodes:
        node_id = node.get('id')
        if not node_id:
            continue
        kind = node.get('kind') or (node.get('kinds') or [None])[0] or 'Unknown'
        # Normalize node id
        if ':' in str(node_id):
            prefix, raw = str(node_id).split(':', 1)
            node_id = uid(prefix, raw)
        else:
            node_id = uid(kind, node_id)
        if not node_id or node_id in seen_node_ids:
            continue
        node['id'] = node_id
        seen_node_ids.add(node_id)
        props = node.get('properties', {}) or {}
        # CRITICAL: BloodHound requires objectid to match node ID exactly
        props['objectid'] = node_id
        display_name = props.get('displayName') or props.get('name') or props.get('email') or node.get('label') or node_id
        props['name'] = display_name
        node['label'] = display_name
        kinds = set(node.get('kinds', []))
        kind = node.get('kind', None) or (next(iter(kinds)) if kinds else None)
        if kind == 'CFUser':
            kinds.add('User')
        elif kind == 'CFGroup':
            kinds.add('Group')
        elif kind == 'CFTeam':
            kinds.add('Group')
        # Asset mapping for both J* and CF* project/issue/role/space
        if kind in ('JProject','JIssue','JRole','CFProject','CFIssue','CFRole','CFSpace'):
            kinds.add('Asset')
        if not kinds and kind:
            kinds.add(kind)
        # CRITICAL: Primary kind must be first, not alphabetically sorted
        # BloodHound uses kinds[0] as primarykind, so ensure the node's primary kind is first
        if kind and kind in kinds:
            kinds_list = [kind] + sorted([k for k in kinds if k != kind])
        else:
            kinds_list = sorted(kinds)
        node['kinds'] = kinds_list
        node['kind'] = kind or (node['kinds'][0] if node['kinds'] else 'Unknown')
        props = {k: v for k, v in props.items() if v is not None and not isinstance(v, dict)}
        node['properties'] = props
        node['high_value'] = node.get('high_value', False)
        clean_nodes.append(node)
    nodes = sorted(clean_nodes, key=lambda n: n['id'])
    node_ids = {n['id'] for n in nodes}
    source_kind = getattr(graph, "source_kind", None)

    # --- Collect and sanitize edges ---
    edges_raw = getattr(graph, 'edges', [])
    seen_edge_ids = set()
    clean_edges = []
    self_ref_count = 0
    for e in edges_raw:
        edge = e.to_dict() if hasattr(e, 'to_dict') else dict(e)
        start = edge.get('start') or edge.get('source')
        end = edge.get('end') or edge.get('target')
        # Normalize endpoint IDs
        start_kind = edge.get('start_kind') or edge.get('kind')
        end_kind = edge.get('end_kind') or edge.get('kind')
        if isinstance(start, str):
            # Try to split if already has a colon
            if ':' in start:
                prefix, raw = start.split(':', 1)
                start = {'value': uid(prefix, raw), 'match_by': 'id'}
            else:
                start = {'value': uid(start_kind or '', start), 'match_by': 'id'}
        if isinstance(end, str):
            if ':' in end:
                prefix, raw = end.split(':', 1)
                end = {'value': uid(prefix, raw), 'match_by': 'id'}
            else:
                end = {'value': uid(end_kind or '', end), 'match_by': 'id'}
        edge['start'] = start
        edge['end'] = end

        # CRITICAL: Skip self-referencing edges (prevents graph visualization issues)
        start_id = edge['start']['value']
        end_id = edge['end']['value']
        if start_id == end_id:
            self_ref_count += 1
            continue
        kinds = set(edge.get('kinds', []))
        kind = edge.get('kind', None) or (next(iter(kinds)) if kinds else None)
        if kind == 'CFMemberOfGroup':
            kinds.add('MemberOf')
        elif kind == 'CFMemberOfTeam':
            kinds.add('MemberOf')
        edge['kinds'] = sorted(kinds) if kinds else [kind or 'unknown']
        edge['kind'] = kind or (edge['kinds'][0] if edge['kinds'] else 'unknown')
        edge['label'] = edge['kind']  # BloodHound 5 uses 'label' for relationship type display
        if 'id' not in edge:
            edge['id'] = f"{edge['kind']}:{edge['start']['value']}->{edge['end']['value']}"
        if edge['id'] in seen_edge_ids:
            continue
        seen_edge_ids.add(edge['id'])
        props = edge.get('properties', {}) or {}
        props = {k: v for k, v in props.items() if v is not None and not isinstance(v, dict)}

        # Add string versions of array properties for BloodHound UI compatibility
        # Keep arrays for data preservation, add *_str for display
        for key, value in list(props.items()):
            if isinstance(value, list):
                # Skip if we already have a _str version
                if f"{key}_str" in props:
                    continue
                # Convert homogeneous string arrays to comma-separated strings
                if all(isinstance(item, str) for item in value):
                    props[f"{key}_str"] = ", ".join(value)
                else:
                    # Mixed types or non-strings - convert to string representation
                    props[f"{key}_str"] = ", ".join(str(item) for item in value)

        edge['properties'] = props
        clean_edges.append(edge)
    edges = clean_edges

    if self_ref_count > 0:
        logging.info(f"[EXPORT] Filtered {self_ref_count} self-referencing edges")

    mirror_config = _load_mirror_config()
    if mirror_bh_edges:
        edges.extend(mirror_bloodhound_edges(edges, nodes, mirror_config))

    # Dedupe all edges by id after all mirrors are added
    initial_edge_count = len(edges)
    uniq = {}
    for e in edges:
        uniq[e['id']] = e
    edges = list(uniq.values())
    dup_count = initial_edge_count - len(edges)
    if dup_count > 0:
        logging.info(f"[EXPORT] Removed {dup_count} duplicate edges")
    # Drop edges where either endpoint is missing
    def _valid(e):
        return e['start']['value'] in node_ids and e['end']['value'] in node_ids
    edges = [e for e in edges if _valid(e)]
    edges = sorted(edges, key=lambda e: e['id'])

    # --- Admin detection and high_value tagging (if enabled) ---
    if mirror_bh_edges:
        # Build id->kinds map for case-insensitive detection
        id_to_kinds = {n['id']: set(n.get('kinds', [])) | {n.get('kind', '')} for n in nodes}
        def is_user(node_id):
            kinds = id_to_kinds.get(node_id, set())
            return 'CFUser' in kinds or 'User' in kinds
        def is_group(node_id):
            kinds = id_to_kinds.get(node_id, set())
            return any(k in kinds for k in ('CFGroup','Group','CFTeam'))
        admin_user_ids = set()
        admin_group_ids = set()
        admin_role_users = set()
        for edge in edges:
            if edge['kind'] == 'CFHasPermission':
                props = edge.get('properties', {}) or {}
                perms = props.get('permissions')
                if not perms and props.get('permission'):
                    perms = [props['permission']]
                if isinstance(perms, str):
                    perms = [perms]
                if perms and any('administer' in p.lower() or 'admin' in p.lower() for p in perms if isinstance(p, str)):
                    start_id = edge['start']['value']
                    if is_user(start_id):
                        admin_user_ids.add(start_id)
                    elif is_group(start_id):
                        admin_group_ids.add(start_id)
            if edge['kind'] == 'JAssignedToRole':
                start_id = edge['start']['value']
                admin_role_users.add(start_id)
        for node in nodes:
            node_id = node.get('id', '')
            if node_id in admin_user_ids or node_id in admin_group_ids or node_id in admin_role_users:
                node['high_value'] = True
            elif 'high_value' not in node:
                node['high_value'] = False
        # (No second mirroring here; already mirrored and deduped above)

    # --- Identity normalization: SameUser edges ---
    email_to_ids = {}
    for node in nodes:
        email = node.get('properties', {}).get('emailAddress') or node.get('properties', {}).get('email')
        if email:
            email = email.lower()
            email_to_ids.setdefault(email, []).append(node['id'])
    sameuser_edges = []
    for email, ids in email_to_ids.items():
        if len(ids) > 1:
            for i in range(len(ids)):
                for j in range(i+1, len(ids)):
                    sameuser_edges.append({
                        'id': f"SameUser:{ids[i]}->{ids[j]}",
                        'kinds': ['SameUser'],
                        'kind': 'SameUser',
                        'start': {'value': ids[i], 'match_by': 'id'},
                        'end': {'value': ids[j], 'match_by': 'id'},
                        'properties': {'email': email}
                    })
    edges.extend(sameuser_edges)
    # Dedupe again after adding SameUser edges
    uniq = {}
    for e in edges:
        uniq[e['id']] = e
    edges = sorted(uniq.values(), key=lambda e: e['id'])

    # --- Apply MITRE ATT&CK mappings ---
    from .attack_mapper import apply_attack_mapping
    apply_attack_mapping(edges)

    # --- Add canonical BloodHound edges for UI compatibility ---
    canonical_edges = _create_canonical_edges(edges, nodes)
    if canonical_edges:
        logging.info(f"[EXPORT] Created {len(canonical_edges)} canonical BloodHound edges for UI compatibility")
        edges.extend(canonical_edges)
        # Dedupe after adding canonical edges
        uniq = {}
        for e in edges:
            uniq[e['id']] = e
        edges = sorted(uniq.values(), key=lambda e: e['id'])

    # --- Validation ---
    REQUIRED_NODE_FIELDS = {"id", "kinds"}
    REQUIRED_EDGE_FIELDS = {"start", "end", "kind"}
    node_errors = [(n.get('id'), f"Missing: {REQUIRED_NODE_FIELDS - set(n.keys())}") for n in nodes if REQUIRED_NODE_FIELDS - set(n.keys())]
    edge_errors = [(e.get('id'), f"Missing: {REQUIRED_EDGE_FIELDS - set(e.keys())}") for e in edges if REQUIRED_EDGE_FIELDS - set(e.keys())]
    if node_errors or edge_errors:
        logging.error(f"[EXPORT VALIDATION] Node errors: {node_errors}")
        logging.error(f"[EXPORT VALIDATION] Edge errors: {edge_errors}")
    else:
        logging.info("[EXPORT VALIDATION] All nodes and edges passed schema checks.")

    # --- Output ---
    metadata: Dict[str, Any] = {
        "generator": "AtlassianHound",
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "source_kind": "ATLBase",  # Official source kind for Atlassian Cloud data
    }
    # Override with graph-level source_kind if available
    if source_kind:
        metadata["source_kind"] = source_kind
    if collector_errors:
        metadata["collector_errors"] = collector_errors
    if extra_metadata:
        metadata.update(extra_metadata)
    output = {
        "graph": {"nodes": nodes, "edges": edges},
        "metadata": metadata,
    }
    try:
        test_json = json.dumps(output, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error(f"[EXPORT ERROR] Output is not serializable: {e}")
        raise
    if filename:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(test_json)
        logging.info(f"Graph exported to %s", filename)
    return output

# --- Mirroring logic (from mirroring.py) ---
def mirror_bloodhound_edges(edges, nodes, mirror_config: Dict[str, Any]):
    mirrored = []
    seen = set()
    # Build kinds_by_id for robust direction logic
    kinds_by_id = {n['id']: set(n.get('kinds', [])) | {n.get('kind', '')} for n in nodes}
    def is_user(nid):
        return 'User' in kinds_by_id.get(nid, set())
    def is_group(nid):
        return 'Group' in kinds_by_id.get(nid, set()) or 'Team' in kinds_by_id.get(nid, set())
    for e in edges:
        edge_kinds = set(e.get('kinds', []))
        edge_kind = e.get('kind')
        if edge_kind:
            edge_kinds.add(edge_kind)
        if 'CFMemberOfGroup' in edge_kinds:
            start_id = e['start']['value']
            end_id = e['end']['value']
            if is_user(start_id) and is_group(end_id):
                s, t = e['start'], e['end']
            elif is_group(start_id) and is_user(end_id):
                s, t = e['end'], e['start']
            else:
                s, t = e['start'], e['end']
            mid = f"MemberOf:{s['value']}->{t['value']}"
            if mid not in seen:
                mirrored.append({
                    'id': mid,
                    'kinds': ['MemberOf'],
                    'kind': 'MemberOf',
                    'start': s,
                    'end': t,
                    'properties': {'source': 'mirror', 'from': 'CFMemberOfGroup'}
                })
                seen.add(mid)
        if 'CFMemberOfTeam' in edge_kinds:
            start_id = e['start']['value']
            end_id = e['end']['value']
            if is_user(start_id) and is_group(end_id):
                s, t = e['start'], e['end']
            elif is_group(start_id) and is_user(end_id):
                s, t = e['end'], e['start']
            else:
                s, t = e['start'], e['end']
            mid = f"MemberOf:{s['value']}->{t['value']}"
            if mid not in seen:
                mirrored.append({
                    'id': mid,
                    'kinds': ['MemberOf'],
                    'kind': 'MemberOf',
                    'start': s,
                    'end': t,
                    'properties': {'source': 'mirror', 'from': 'CFMemberOfTeam'}
                })
                seen.add(mid)
    permission_rules = mirror_config.get("CFHasPermission") or [
        {"edge": "AdminTo", "match": ["administer", "admin"]},
        {"edge": "GenericWrite", "match": ["edit", "write"]},
    ]
    compiled_rules: List[Tuple[Dict[str, Any], Optional[re.Pattern[str]]]] = []
    for rule in permission_rules:
        match = rule.get("match")
        pattern: Optional[re.Pattern[str]] = None
        if isinstance(match, str):
            pattern = re.compile(match, re.I)
        elif isinstance(match, (list, tuple)) and match:
            pattern = re.compile("|".join(re.escape(str(x)) for x in match), re.I)
        compiled_rules.append((rule, pattern))
    for e in edges:
        edge_kinds = set(e.get('kinds', []))
        edge_kind = e.get('kind')
        if edge_kind:
            edge_kinds.add(edge_kind)
        if 'CFHasPermission' in edge_kinds:
            props = e.get('properties', {}) or {}
            perms = props.get('permissions', [])
            if isinstance(perms, str):
                perms = [perms]
            perms = [p.lower() for p in perms if isinstance(p, str)]
            for rule, pattern in compiled_rules:
                if not pattern:
                    continue
                if any(pattern.search(p) for p in perms):
                    edge_kind = rule.get("edge")
                    if not edge_kind:
                        continue
                    mid = f"{edge_kind}:{e['start']['value']}->{e['end']['value']}"
                    if mid in seen:
                        continue
                    properties = {'source': 'mirror', 'from': 'CFHasPermission'}
                    rule_props = rule.get("properties")
                    if isinstance(rule_props, dict):
                        properties.update(rule_props)
                    mirrored.append({
                        'id': mid,
                        'kinds': [edge_kind],
                        'kind': edge_kind,
                        'start': e['start'],
                        'end': e['end'],
                        'properties': properties
                    })
                    seen.add(mid)
    reverse_edges = []
    reverse_enabled = mirror_config.get("reverse_edges", {}).get("MemberOf", True)
    for e in edges:
        edge_kinds = set(e.get('kinds', []))
        edge_kind = e.get('kind')
        if edge_kind:
            edge_kinds.add(edge_kind)
        if 'JCreated' in edge_kinds:
            mid = f"Owns:{e['start']['value']}->{e['end']['value']}"
            if mid not in seen:
                mirrored.append({
                    'id': mid,
                    'kinds': ['Owns'],
                    'kind': 'Owns',
                    'start': e['start'],
                    'end': e['end'],
                    'properties': {'source': 'mirror', 'from': 'JCreated'}
                })
                seen.add(mid)
    if reverse_enabled:
        for mirrored_edge in list(mirrored):
            if mirrored_edge['kind'] == 'MemberOf':
                reverse_id = f"MemberOfReverse:{mirrored_edge['end']['value']}->{mirrored_edge['start']['value']}"
                if reverse_id not in seen:
                    reverse_edges.append({
                        'id': reverse_id,
                        'kinds': ['MemberOfReverse'],
                        'kind': 'MemberOfReverse',
                        'start': mirrored_edge['end'],
                        'end': mirrored_edge['start'],
                        'properties': {'source': 'mirror', 'from': mirrored_edge['kind']},
                    })
                    seen.add(reverse_id)
        mirrored.extend(reverse_edges)
    return mirrored


@lru_cache(maxsize=1)
def _load_mirror_config() -> Dict[str, Any]:
    path = Path("model.json")
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:  # pragma: no cover - fall back silently
        logging.debug("Unable to load mirror configuration: %s", exc)
        return {}
    return data.get("mirrors", {}) or {}
