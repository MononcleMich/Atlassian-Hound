#!/usr/bin/env python3
"""
HoundPaint – Standalone BloodHound registrar & post-ingest helper.

STANDALONE: This script has NO dependencies on the AtlassianHound repo structure.
Just copy it along with model.json and your open_graph.json to any machine with BloodHound.

Features:
  * Optional BloodHound health check before any API calls.
  * Custom node kind and saved query registration (idempotent).
  * Automatic OpenGraph upload and analytics summary.
  * Post-ingest Cypher fix-ups executed through /api/v2/graphs/cypher.

Compatible with BloodHound CE v8.2+ and Enterprise v5.x.

Usage:
  python houndpaint.py -s http://localhost:8080 --api-id <TOKEN_ID> --api-key <TOKEN_KEY> --auto-upload open_graph.json --register --analytics-summary
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import pathlib
import sys
from typing import Any, Dict, List, Optional

import requests


# ============================================================================
# STANDALONE HELPERS (inlined from utils/bhcompat.py)
# ============================================================================

_KNOWN_ICON_MAP = {
    "account": "user",
    "account-circle": "user",
    "account-outline": "user",
    "account-group": "users",
    "account-multiple": "users",
    "account-multiple-outline": "users",
    "account-box": "user",
    "user": "user",
    "users": "users",
    "people-group": "people-group",
    "book-open": "book-open",
    "folder-open": "folder-open",
    "alert-circle": "circle-exclamation",
    "shield": "shield-halved",
    "shield-alt": "shield-halved",
    "shield-half-full": "shield-halved",
    "key": "key",
    "cloud": "cloud",
    "circle-exclamation": "circle-exclamation",
    "triangle-exclamation": "triangle-exclamation",
    "bolt": "bolt",
    "file-alt": "file-lines",
    "webhook": "share-nodes",
    "life-ring": "life-ring",
    "layer-group": "layer-group",
    "user-shield": "user-shield",
    "user-secret": "user-secret",
    "user-circle": "user",
    "book-outline": "book-open",
}


def _normalise_icon_name(icon: Optional[str]) -> str:
    """Normalize icon names for BloodHound compatibility."""
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
    """Normalize color codes for BloodHound compatibility."""
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

        if not searchable:
            searchable = ["name"]

        custom_types[kind] = {
            "icon": {
                "name": icon_name,
                "type": "font-awesome",
                "color": color,
            },
            "display_property": display_property,
            "searchable_properties": sorted(set(searchable)),
        }
    return custom_types


# ============================================================================
# COLORS & FORMATTING
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    CYAN = '\033[36m'
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

def print_success(msg: str) -> None:
    """Print success message in green with checkmark."""
    msg_clean = msg.encode('ascii', 'ignore').decode('ascii').strip()
    print(f"{Colors.GREEN}[OK]{Colors.RESET} {msg_clean}")

def print_info(msg: str) -> None:
    """Print info message in cyan."""
    msg_clean = msg.encode('ascii', 'ignore').decode('ascii').strip()
    print(f"{Colors.CYAN}[INFO]{Colors.RESET} {msg_clean}")

def print_warning(msg: str) -> None:
    """Print warning message in yellow."""
    msg_clean = msg.encode('ascii', 'ignore').decode('ascii').strip()
    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {msg_clean}")

def print_error(msg: str) -> None:
    """Print error message in red."""
    msg_clean = msg.encode('ascii', 'ignore').decode('ascii').strip()
    print(f"{Colors.RED}[ERROR]{Colors.RESET} {msg_clean}")

def print_header(msg: str) -> None:
    """Print section header."""
    # Remove emoji to avoid Windows encoding issues
    msg_clean = msg.encode('ascii', 'ignore').decode('ascii').strip()
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {msg_clean}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")

def print_subheader(msg: str) -> None:
    """Print subsection header."""
    msg_clean = msg.encode('ascii', 'ignore').decode('ascii').strip()
    print(f"\n{Colors.DIM}{'-'*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{msg_clean}{Colors.RESET}")
    print(f"{Colors.DIM}{'-'*70}{Colors.RESET}")


# ============================================================================
# BLOODHOUND API HELPERS
# ============================================================================

def build_signed_headers(
    api_id: str,
    api_key: str,
    method: str,
    path: str,
    body: Optional[bytes] = None,
    content_type: Optional[str] = None,
) -> Dict[str, str]:
    now = datetime.datetime.now(datetime.timezone.utc).astimezone()
    request_date = now.isoformat("T")

    key_bytes = api_key.encode("utf-8")
    step = hmac.new(key_bytes, None, hashlib.sha256)
    step.update(f"{method.upper()}{path}".encode("utf-8"))

    step = hmac.new(step.digest(), None, hashlib.sha256)
    step.update(request_date[:13].encode("utf-8"))

    step = hmac.new(step.digest(), None, hashlib.sha256)
    if body:
        step.update(body)

    signature = base64.b64encode(step.digest()).decode("ascii")

    headers = {
        "Authorization": f"bhesignature {api_id}",
        "RequestDate": request_date,
        "Signature": signature,
        "User-Agent": "houndpaint/1.0",
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def api_request(
    server: str,
    api_id: str,
    api_key: str,
    method: str,
    path: str,
    *,
    json_payload: Optional[dict] = None,
    body_text: Optional[str] = None,
    timeout: int = 60,
) -> requests.Response:
    base = server.rstrip("/")
    url = base + path

    body_bytes: Optional[bytes] = None
    content_type: Optional[str] = None

    if json_payload is not None:
        body_text = json.dumps(json_payload, separators=(",", ":"), ensure_ascii=False)
        body_bytes = body_text.encode("utf-8")
        content_type = "application/json"
    elif body_text is not None:
        body_bytes = body_text.encode("utf-8")
        content_type = "application/json"

    headers = build_signed_headers(api_id, api_key, method, path, body=body_bytes, content_type=content_type)

    request_kwargs = {"headers": headers, "timeout": timeout}
    if body_bytes is not None:
        request_kwargs["data"] = body_bytes

    return requests.request(method, url, **request_kwargs)


def get_existing_kinds(server: str, api_id: str, api_key: str) -> List[str]:
    """
    Get all existing custom node kinds from BloodHound.

    Returns:
        List of kind names currently registered in BloodHound.
    """
    try:
        resp = api_request(server, api_id, api_key, "GET", "/api/v2/custom-nodes", timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print_error(f"Failed to fetch existing custom node kinds: {exc}")
        return []

    try:
        payload = resp.json()
    except ValueError:
        print_error("Failed to parse custom node kinds response")
        return []

    kinds: List[str] = []
    if isinstance(payload, dict):
        data_section = payload.get("data", [])
        if isinstance(data_section, list):
            for item in data_section:
                kind_name = item.get("kindName") or item.get("kind") or item.get("kind_name")
                if kind_name:
                    kinds.append(kind_name)

    return kinds


def delete_kind(server: str, api_id: str, api_key: str, kind_name: str) -> bool:
    """
    Delete a single custom node kind from BloodHound.

    Args:
        server: BloodHound server URL
        api_id: API token ID
        api_key: API token secret
        kind_name: The name of the kind to delete

    Returns:
        True if deletion succeeded (200 status), False otherwise.
    """
    try:
        resp = api_request(
            server,
            api_id,
            api_key,
            "DELETE",
            f"/api/v2/custom-nodes/{kind_name}",
            timeout=30,
        )
    except requests.RequestException as exc:
        print_warning(f"Error deleting kind '{kind_name}': {exc}")
        return False

    if resp.status_code == 200:
        return True
    elif resp.status_code == 404:
        # Already deleted or never existed
        return True
    else:
        print_warning(f"Failed to delete '{kind_name}' ({resp.status_code}): {resp.text[:120]}")
        return False


def reset_all_kinds(server: str, api_id: str, api_key: str) -> None:
    """
    Delete ALL existing custom node kinds from BloodHound.

    Useful for getting a clean slate before registering new kinds.
    """
    print_info("Resetting ALL existing custom node kinds...")

    existing_kinds = get_existing_kinds(server, api_id, api_key)

    if not existing_kinds:
        print_info("No existing custom node kinds found to reset")
        return

    print_info(f"Found {len(existing_kinds)} kinds to reset: {existing_kinds}")

    deleted_count = 0
    for kind in existing_kinds:
        if delete_kind(server, api_id, api_key, kind):
            print_success(f"Deleted custom node kind: {kind}")
            deleted_count += 1

    print_info(f"Reset complete: {deleted_count}/{len(existing_kinds)} kinds deleted")


def get_existing_queries(server: str, api_id: str, api_key: str) -> List[Dict[str, str]]:
    """
    Get all existing saved queries from BloodHound.

    Returns:
        List of dicts with 'id' and 'name' keys for each saved query.
    """
    try:
        resp = api_request(server, api_id, api_key, "GET", "/api/v2/saved-queries", timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print_error(f"Failed to fetch existing saved queries: {exc}")
        return []

    try:
        payload = resp.json()
    except ValueError:
        print_error("Failed to parse saved queries response")
        return []

    queries: List[Dict[str, str]] = []
    if isinstance(payload, dict):
        data_section = payload.get("data", [])
        if isinstance(data_section, list):
            for item in data_section:
                query_id = item.get("id")
                query_name = item.get("name")
                if query_id and query_name:
                    queries.append({"id": str(query_id), "name": query_name})

    return queries


def delete_query(server: str, api_id: str, api_key: str, query_id: str, query_name: str = "") -> bool:
    """
    Delete a single saved query from BloodHound.

    Args:
        server: BloodHound server URL
        api_id: API token ID
        api_key: API token secret
        query_id: The ID of the query to delete
        query_name: Optional name for logging

    Returns:
        True if deletion succeeded (200 status), False otherwise.
    """
    display_name = query_name or query_id
    try:
        resp = api_request(
            server,
            api_id,
            api_key,
            "DELETE",
            f"/api/v2/saved-queries/{query_id}",
            timeout=30,
        )
    except requests.RequestException as exc:
        print_warning(f"Error deleting query '{display_name}': {exc}")
        return False

    if resp.status_code in (200, 204):
        # 200 OK or 204 No Content = success
        return True
    elif resp.status_code == 404:
        # Already deleted or never existed
        return True
    else:
        print_warning(f"Failed to delete query '{display_name}' ({resp.status_code}): {resp.text[:120]}")
        return False


def reset_all_queries(server: str, api_id: str, api_key: str) -> None:
    """
    Delete ALL existing saved queries from BloodHound.

    Useful for getting a clean slate before registering new queries.
    """
    print_info("🔄 Resetting ALL existing saved queries...")

    existing_queries = get_existing_queries(server, api_id, api_key)

    if not existing_queries:
        print_info("ℹ️  No existing saved queries found to reset")
        return

    query_names = [q["name"] for q in existing_queries]
    print_info(f"Found {len(existing_queries)} queries to reset: {query_names}")

    deleted_count = 0
    for query in existing_queries:
        if delete_query(server, api_id, api_key, query["id"], query["name"]):
            print_success(f"🗑️  Deleted saved query: {query['name']}")
            deleted_count += 1

    print_info(f"Reset complete: {deleted_count}/{len(existing_queries)} queries deleted")


def _read_versions(version_resp: requests.Response) -> Dict[str, str]:
    try:
        body = version_resp.json()
    except ValueError:
        body = {}

    data = body.get("data", {}) if isinstance(body, dict) else {}
    server_version = (
        data.get("server_version")
        or body.get("server_version")
        or body.get("version")
        or "?"
    )
    api_version = (
        data.get("API", {}).get("current_version")
        or data.get("api_version")
        or body.get("api_version")
        or "?"
    )
    return {"server": server_version, "api": api_version}


def detect_edition(server: str, api_id: str, api_key: str) -> str:
    try:
        resp = api_request(server, api_id, api_key, "GET", "/api/v2/license", timeout=15)
    except requests.RequestException:
        return "Unknown"

    if resp.status_code == 404:
        return "Community"
    if resp.ok:
        data = {}
        try:
            data = resp.json()
        except ValueError:
            return "Unknown"
        return data.get("edition", "Enterprise")
    return "Unknown"


def health_check(server: str, api_id: str, api_key: str) -> None:
    """Verify the BloodHound API is reachable and print the reported version and edition."""
    try:
        version_resp = api_request(server, api_id, api_key, "GET", "/api/version", timeout=15)
        version_resp.raise_for_status()
    except requests.RequestException as exc:
        print_error(f"Health check failed: {exc}")
        sys.exit(1)

    versions = _read_versions(version_resp)
    edition = detect_edition(server, api_id, api_key)
    print_success(
        f"Connected to BloodHound {Colors.BOLD}{edition}{Colors.RESET} Edition "
        f"(Server v{versions['server']}, API v{versions['api']})"
    )


def auto_upload(server: str, api_id: str, api_key: str, path: str) -> None:
    """Upload an OpenGraph JSON export directly into BloodHound."""
    print_subheader("Uploading OpenGraph Data")

    graph_path = pathlib.Path(path)
    if not graph_path.is_file():
        print_error(f"Graph file not found: {graph_path}")
        return

    file_size_kb = graph_path.stat().st_size / 1024
    print_info(f"Reading {graph_path.name} ({file_size_kb:.1f} KB)...")

    try:
        body_text = graph_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print_error(f"Failed to read graph file: {exc}")
        return

    print_info(f"Uploading to {server}/api/v2/ingest...")

    try:
        resp = api_request(
            server,
            api_id,
            api_key,
            "POST",
            "/api/v2/ingest",
            body_text=body_text,
            timeout=120,
        )
    except requests.RequestException as exc:
        print_error(f"Upload error: {exc}")
        return

    if resp.ok:
        print_success(f"Graph uploaded successfully ({file_size_kb:.1f} KB)")
    else:
        print_error(f"Upload failed ({resp.status_code}): {resp.text[:200]}")


def analytics_summary(server: str, api_id: str, api_key: str) -> None:
    """Fetch graph analytics to confirm node/edge counts post-import."""
    try:
        resp = api_request(server, api_id, api_key, "GET", "/api/v2/analytics", timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print_error(f"Analytics check failed: {exc}")
        return

    stats = resp.json()
    nodes = stats.get("nodeCount", 0)
    edges = stats.get("edgeCount", 0)
    print_info(f"Graph summary: {nodes} nodes / {edges} edges")


def register_custom_nodes(
    server: str,
    api_id: str,
    api_key: str,
    model: dict,
) -> None:
    """Register custom node kinds using visuals from model.json."""
    print_subheader("Registering Custom Node Types")

    custom_types = build_custom_types(model)
    if not custom_types:
        print_info("No custom node kinds defined; skipping registration.")
        return
    base_path = "/api/v2/custom-nodes"

    registered = 0
    updated = 0
    registered_kinds = []

    for kind, config in custom_types.items():
        payload = {"custom_types": {kind: config}}
        try:
            resp = api_request(
                server,
                api_id,
                api_key,
                "POST",
                base_path,
                json_payload=payload,
                timeout=30,
            )
        except requests.RequestException as exc:
            print_error(f"Failed to register custom node kind '{kind}': {exc}")
            continue

        if resp.status_code in (200, 201):
            print_success(f"Registered custom node kind: {kind}")
            registered += 1
            registered_kinds.append(kind)
            continue

        lower_body = resp.text.lower()
        if resp.status_code == 409:
            print_info(f"ℹ️  Custom node kind '{kind}' already registered")
            # Try to update it
            try:
                put_resp = api_request(
                    server,
                    api_id,
                    api_key,
                    "PUT",
                    f"{base_path}/{kind}",
                    json_payload=config,
                    timeout=30,
                )
            except requests.RequestException as exc:
                print_error(f"Failed to update existing node kind '{kind}': {exc}")
                continue

            if put_resp.status_code in (200, 201):
                print_success(f"Updated existing node kind: {kind}")
                updated += 1
                registered_kinds.append(kind)
            else:
                print_warning(f"Could not update node kind '{kind}' ({put_resp.status_code}): {put_resp.text}")
            continue

        if resp.status_code == 400 and ("duplicate" in lower_body or "exists" in lower_body):
            print_info(f"ℹ️  Custom node kind '{kind}' already exists")
            continue

        # Print FULL error response for debugging
        print_error(f"Custom node kind '{kind}' failed ({resp.status_code}):")
        print_error(f"Full response: {resp.text}")

    # Print summary with count and list of registered kinds
    if registered:
        print_success(f"✅ Successfully registered {registered} custom node kinds")
        for kind in registered_kinds[:registered]:
            print_info(f"   📌 {kind}")
    if updated:
        print_success(f"✅ Successfully updated {updated} existing custom node kinds")
        for kind in registered_kinds[registered:]:
            print_info(f"   📌 {kind}")


def register_saved_queries(server: str, api_id: str, api_key: str, model: dict) -> None:
    """Register saved queries from model.json."""
    queries = model.get("saved_queries", [])
    if not queries:
        print_info("No saved queries defined; skipping.")
        return

    print_info(f"Registering {len(queries)} saved queries...")
    for entry in queries:
        name = entry.get("name")
        query_text = entry.get("cypher")
        if not (name and query_text):
            continue

        payload = {
            "name": name,
            "description": entry.get("description", ""),
            "query": query_text,
        }

        try:
            resp = api_request(
                server,
                api_id,
                api_key,
                "POST",
                "/api/v2/saved-queries",
                json_payload=payload,
                timeout=30,
            )
        except requests.RequestException as exc:
            print_error(f"Failed to register query '{name}': {exc}")
            continue

        if resp.status_code in (200, 201):
            print_success(f"Query added: {name}")
            continue

        body_text = resp.text.lower()
        if resp.status_code == 409 or ("duplicate name" in body_text):
            print_info(f"Query already exists: {name}")
            continue

        short_msg = ""
        try:
            error_payload = resp.json()
            errors = error_payload.get("errors")
            if isinstance(errors, list) and errors:
                short_msg = errors[0].get("message", "")
        except ValueError:
            short_msg = ""
        short_msg = (short_msg or resp.text).strip()
        if len(short_msg) > 120:
            short_msg = short_msg[:117] + "..."
        print_warning(f"Query '{name}' returned {resp.status_code}: {short_msg}")


def run_cypher_query(server: str, api_id: str, api_key: str, query: str, name: str | None = None) -> None:
    """Execute Cypher via BloodHound's /api/v2/graphs/cypher endpoint."""
    base = server.rstrip("/")
    payload = {"query": query, "include_properties": True}

    try:
        resp = api_request(
            server,
            api_id,
            api_key,
            "POST",
            "/api/v2/graphs/cypher",
            json_payload=payload,
            timeout=60,
        )
    except requests.RequestException as exc:
        print_error(f"Network error executing '{name or query[:40]}…': {exc}")
        return

    if resp.status_code != 200:
        print_error(f"Fix-up '{name or 'unnamed'}' failed ({resp.status_code}) → {resp.text[:300]}")
        return

    try:
        result = resp.json()
    except ValueError:
        print_error(f"Fix-up '{name or 'unnamed'}' returned non-JSON response.")
        return

    data = result.get("data", {})
    node_count = len(data.get("nodes", {}))
    edge_count = len(data.get("edges", []))
    print_success(f"Fix-up '{name or query[:50]}…' executed ({node_count} nodes, {edge_count} edges)")


def run_post_ingest_fixups(server: str, api_id: str, api_key: str, model: dict) -> None:
    """Iterate over post-ingest Cypher fix-ups defined in model.json."""
    print_subheader("Running Post-Ingest Fix-Ups")

    edition = detect_edition(server, api_id, api_key)
    print_info(f"Connected to BloodHound {edition} Edition")

    normalized = edition.strip().lower()
    if normalized == "community" or normalized.startswith("community "):
        print_info("Community Edition detected; skipping post-ingest fix-ups (mutating Cypher unsupported).")
        return

    cypher_sets = model.get("post_ingest_cypher", {})
    if not cypher_sets:
        print_info("No post-ingest Cypher fix-ups defined in model.json; skipping.")
        return

    for section, queries in cypher_sets.items():
        print_info(f"Section: {section}")
        for entry in queries:
            query = entry.get("cypher")
            if not query:
                continue
            run_cypher_query(server, api_id, api_key, query, entry.get("name"))

    print_success("All post-ingest fix-ups completed")


def load_model_json(path: str) -> dict:
    """Load model.json from disk."""
    model_path = pathlib.Path(path)
    try:
        content = model_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print_error(f"Model file not found: {model_path}")
        sys.exit(1)
    except OSError as exc:
        print_error(f"Failed to read model file '{model_path}': {exc}")
        sys.exit(1)

    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        print_error(f"Invalid JSON in '{model_path}': {exc}")
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Register visuals, upload graph data, and run BloodHound fix-ups."
    )
    parser.add_argument(
        "-s",
        "--server",
        required=True,
        help="BloodHound base URL, e.g. http://localhost:8080",
    )
    parser.add_argument("--api-id", required=True, help="BloodHound API token ID")
    parser.add_argument("--api-key", required=True, help="BloodHound API token secret (Base64 HMAC key)")
    parser.add_argument("--model", default="model.json", help="Path to model.json")
    parser.add_argument("--register", action="store_true", help="Register node kinds & saved queries")
    parser.add_argument(
        "--force-replace",
        action="store_true",
        help="Delete all existing custom node kinds before registration (deprecated, use --reset)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete ALL existing custom node kinds before registering new ones",
    )
    parser.add_argument(
        "--list-existing",
        action="store_true",
        help="List all registered custom node types and exit",
    )
    parser.add_argument(
        "--list-queries",
        action="store_true",
        help="List all registered saved queries and exit",
    )
    parser.add_argument(
        "--reset-queries",
        action="store_true",
        help="Delete ALL existing saved queries before registering new ones",
    )
    parser.add_argument("--post-ingest-fixups", action="store_true", help="Run Cypher fix-ups from model.json")
    parser.add_argument("--health-check", action="store_true", help="Ping BloodHound before starting")
    parser.add_argument(
        "--auto-upload",
        metavar="PATH",
        help="Upload an OpenGraph JSON file to BloodHound before registration/fix-ups",
    )
    parser.add_argument(
        "--analytics-summary",
        action="store_true",
        help="Print graph node/edge counts after operations complete",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Handle --list-existing flag (exit early)
    if args.list_existing:
        print_header("📋 Listing Existing Custom Node Kinds")
        existing_kinds = get_existing_kinds(args.server, args.api_id, args.api_key)
        if existing_kinds:
            print_success(f"Found {len(existing_kinds)} custom node kinds:")
            for kind in existing_kinds:
                print_info(f"   • {kind}")
        else:
            print_info("No custom node kinds found")
        return 0

    # Handle --list-queries flag (exit early)
    if args.list_queries:
        print_header("📋 Listing Existing Saved Queries")
        existing_queries = get_existing_queries(args.server, args.api_id, args.api_key)
        if existing_queries:
            print_success(f"Found {len(existing_queries)} saved queries:")
            for query in existing_queries:
                print_info(f"   • {query['name']} (ID: {query['id']})")
        else:
            print_info("No saved queries found")
        return 0

    model = load_model_json(args.model)

    if args.health_check:
        health_check(args.server, args.api_id, args.api_key)

    # Handle --reset flag (delete all existing kinds)
    if args.reset or args.force_replace:
        if args.reset:
            print_header("🔄 Resetting Custom Node Kinds")
        reset_all_kinds(args.server, args.api_id, args.api_key)

    # Handle --reset-queries flag (delete all existing queries)
    if args.reset_queries:
        print_header("🔄 Resetting Saved Queries")
        reset_all_queries(args.server, args.api_id, args.api_key)

    if args.auto_upload:
        auto_upload(args.server, args.api_id, args.api_key, args.auto_upload)

    if args.register:
        register_custom_nodes(
            args.server,
            args.api_id,
            args.api_key,
            model,
        )
        register_saved_queries(args.server, args.api_id, args.api_key, model)

    if args.post_ingest_fixups:
        run_post_ingest_fixups(args.server, args.api_id, args.api_key, model)

    if args.analytics_summary:
        analytics_summary(args.server, args.api_id, args.api_key)

    if not any(
        [
            args.health_check,
            args.auto_upload,
            args.register,
            args.post_ingest_fixups,
            args.analytics_summary,
            args.list_existing,
            args.reset,
        ]
    ):
        print_info("Nothing to do. Supply --register, --post-ingest-fixups, or other actions.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
