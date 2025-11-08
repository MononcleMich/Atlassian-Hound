from __future__ import annotations

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from bhopengraph.OpenGraph import OpenGraph

from collectors import (
    application_roles_collector,
    apps_collector,
    confluence_restrictions_collector,
    global_permissions_collector,
    groups_collector,
    jsm_collector,
    org_admin_collector,
    permissions_collector,
    projects_collector,
    security_schemes_collector,
    spaces_collector,
    teams_collector,
    users_collector,
    watchers_collector,
    webhooks_collector,
)
from utils import common
from utils.analyzers import apply_privilege_analytics
from utils.config_loader import load_config, merge_settings
from utils.export import export_graph
from utils.diagnostics import run_diagnostics

LOG = logging.getLogger("AtlassianHound")
VERSION = "1.0.5"

DEFAULT_COLLECTORS: Sequence[str] = (
    "users",
    "groups",
    "teams",
    "spaces",
    "projects",
    "permissions",
    "global_permissions",
    "org_admin",
    "application_roles",
    "jsm",
    "confluence_restrictions",
    "watchers",
    "webhooks",
    "security_schemes",
    "apps",
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(payload, ensure_ascii=False)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for terminal output."""

    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    def __init__(self, debug_mode: bool = False):
        self.debug_mode = debug_mode
        if debug_mode:
            fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        else:
            # Cleaner format without timestamp and simplified logger name
            fmt = "%(message)s"
        super().__init__(fmt)

    def format(self, record: logging.LogRecord) -> str:
        # Get the fully formatted message first (this handles % formatting)
        message = record.getMessage()

        # Get color for level
        color = self.COLORS.get(record.levelname, '')

        if not self.debug_mode:
            # Clean format: just colored symbols and message
            symbol_map = {
                'DEBUG': '  ',
                'INFO': '✓',
                'WARNING': '⚠',
                'ERROR': '✗',
                'CRITICAL': '✗',
            }
            symbol = symbol_map.get(record.levelname, '•')

            # Simplify logger names
            logger_name = record.name.replace('AtlassianHound.', '')
            if logger_name == 'AtlassianHound':
                # Main logger messages - just show the message
                return f"{color}{symbol}{self.RESET} {message}"
            else:
                # Collector messages - show collector name in dim
                return f"{color}{symbol}{self.RESET} {self.DIM}[{logger_name}]{self.RESET} {message}"
        else:
            # Debug format: keep full details with colors
            original_levelname = record.levelname
            record.levelname = f"{color}{original_levelname}{self.RESET}"
            result = super().format(record)
            record.levelname = original_levelname
            return result


def setup_logging(json_mode: bool, level: int = logging.INFO, debug_mode: bool = False) -> None:
    # Set UTF-8 encoding for Windows console
    if sys.platform == 'win32':
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

    handler = logging.StreamHandler(sys.stdout)
    if json_mode:
        formatter = JsonFormatter()
    else:
        formatter = ColoredFormatter(debug_mode=debug_mode)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def main() -> None:
    parser = argparse.ArgumentParser(description="Atlassian-Hound - BloodHound CE Export")
    parser.add_argument("--config", help="Path to configuration file (.toml/.yaml).")
    parser.add_argument(
        "--collect",
        default=",".join(DEFAULT_COLLECTORS),
        help="comma-separated collectors to run (default: all)",
    )
    parser.add_argument(
        "--exclude",
        default="",
        help="comma-separated collectors to skip (overrides defaults/config).",
    )
    parser.add_argument("--output", default=None, help="output directory (default: output/)")
    parser.add_argument(
        "--export-format",
        choices=["opengraph"],
        default="opengraph",
        help="Export format for BloodHound CE. Only 'opengraph' (single-file) is supported.",
    )
    parser.add_argument(
        "--generate-docs",
        action="store_true",
        help="Generate markdown documentation for the OpenGraph model.",
    )
    parser.add_argument(
        "--validate-schema",
        action="store_true",
        help="Validate exported OpenGraph JSON against the schema in model.json.",
    )
    parser.add_argument(
        "--skip-analytics",
        action="store_true",
        help="Disable post-collection privilege analytics.",
    )
    parser.add_argument(
        "--log-json",
        action="store_true",
        help="Emit structured JSON logs.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable per-collector progress messages.",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Run graph diagnostics before export.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Collect and validate without writing an output file.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version information and exit.",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run collectors in parallel for faster collection (experimental).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=4,
        help="Maximum parallel workers when --parallel is enabled (default: 4).",
    )
    parser.add_argument(
        "--test-auth",
        action="store_true",
        help="Test Atlassian API credentials and exit.",
    )
    args = parser.parse_args()

    if args.generate_docs:
        _generate_docs()
        return
    if args.version:
        print(f"AtlassianHound version {VERSION}")
        return
    if args.test_auth:
        _test_credentials()
        return

    config_data = load_config(args.config)
    cli_settings: Dict[str, Dict[str, Iterable[str] | bool]] = {}

    default_collect_value = parser.get_default("collect")
    if args.collect != default_collect_value:
        cli_settings.setdefault("collectors", {})["include"] = _split_csv(args.collect)
    if args.exclude:
        cli_settings.setdefault("collectors", {})["exclude"] = _split_csv(args.exclude)

    logging_overrides: Dict[str, Iterable[str] | bool] = {}
    if args.log_json:
        logging_overrides["json"] = True
    if args.no_progress:
        logging_overrides["progress"] = False
    if args.debug:
        logging_overrides["debug"] = True
    if logging_overrides:
        cli_settings["logging"] = logging_overrides

    settings = merge_settings(config_data, cli_settings) if cli_settings else config_data
    logging_settings = settings.get("logging", {})
    json_logging = bool(logging_settings.get("json", False))
    debug_mode = bool(logging_settings.get("debug", False))
    log_level = logging.DEBUG if debug_mode else logging.INFO
    setup_logging(json_logging, level=log_level, debug_mode=debug_mode)

    _apply_http_settings(settings.get("http", {}))

    enabled_collectors = compute_enabled_collectors(settings.get("collectors", {}))
    if not enabled_collectors:
        LOG.warning("No collectors selected. Exiting.")
        return

    run_start = perf_counter()

    # Print clean header
    print("\n" + "="*70)
    print("  AtlassianHound v{}".format(VERSION))
    print("  Collectors: {}".format(", ".join(enabled_collectors)))
    print("="*70 + "\n")

    progress_enabled = settings.get("logging", {}).get("progress", True)
    diagnostics_requested = args.diagnose or bool(settings.get("diagnostics", {}).get("enabled", False))

    graph = OpenGraph()

    collectors = {
        "users": ("Jira Users", users_collector.run),
        "groups": ("Jira Groups", groups_collector.run),
        "teams": ("Atlassian Teams", teams_collector.run),
        "spaces": ("Confluence Spaces", spaces_collector.run),
        "projects": ("Jira Projects", projects_collector.run),
        "permissions": ("Project Permissions", permissions_collector.run),
        "global_permissions": ("Global Permissions", global_permissions_collector.run),
        "org_admin": ("Organization Roles", org_admin_collector.run),
        "application_roles": ("Application Roles", application_roles_collector.run),
        "jsm": ("Jira Service Management", jsm_collector.run),
        "confluence_restrictions": ("Confluence Restrictions", confluence_restrictions_collector.run),
        "watchers": ("Issue Watchers", watchers_collector.run),
        "webhooks": ("Webhooks", webhooks_collector.run),
        "security_schemes": ("Security Schemes", security_schemes_collector.run),
        "apps": ("Third-Party Apps", apps_collector.run),
    }

    collector_reports: List[Dict[str, Any]] = []
    collector_errors: List[str] = []
    total = len(enabled_collectors)

    if args.parallel:
        LOG.info("Running collectors in parallel with %d workers", args.max_workers)
        with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            future_to_collector = {}
            for collector_key in enabled_collectors:
                meta = collectors.get(collector_key)
                if not meta:
                    LOG.warning("Unknown collector requested: %s", collector_key)
                    continue
                label, func = meta
                future = executor.submit(_execute_collector, label, func, graph)
                future_to_collector[future] = (collector_key, label)

            completed = 0
            for future in as_completed(future_to_collector):
                completed += 1
                collector_key, label = future_to_collector[future]
                if progress_enabled:
                    LOG.info("[Progress] (%d/%d) %s completed", completed, total, label)
                try:
                    duration, error_message = future.result()
                    collector_reports.append({"collector": collector_key, "label": label, "duration": round(duration, 2)})
                    if error_message:
                        collector_errors.append(error_message)
                except Exception as exc:
                    LOG.exception("Collector %s raised exception: %s", label, exc)
                    collector_errors.append(f"{label}: {exc}")
    else:
        for idx, collector_key in enumerate(enabled_collectors, start=1):
            meta = collectors.get(collector_key)
            if not meta:
                LOG.warning("Unknown collector requested: %s", collector_key)
                continue
            label, func = meta
            if progress_enabled:
                print(f"\n[{idx}/{total}] {label}")
                print("-" * 70)
            duration, error_message = _execute_collector(label, func, graph)
            collector_reports.append({"collector": collector_key, "label": label, "duration": round(duration, 2)})
            if error_message:
                collector_errors.append(error_message)

    if not args.skip_analytics:
        print("\n" + "-" * 70)
        LOG.info("Applying privilege analytics and high-value tagging...")
        apply_privilege_analytics(graph)

    diagnostics: Optional[Dict[str, int]] = None
    if diagnostics_requested:
        diagnostics = run_diagnostics(graph)
        print(f"\n✓ Diagnostics: {diagnostics.get('orphan_nodes', 0)} orphans, {diagnostics.get('dangling_edges', 0)} dangling edges, {diagnostics.get('duplicate_edges', 0)} duplicates")

    print("\n" + "-" * 70)
    LOG.info("Exporting BloodHound CE ingest files...")
    outdir = Path(args.output) if args.output else Path("output")
    outdir.mkdir(parents=True, exist_ok=True)

    high_value_count = sum(1 for node in getattr(graph, "nodes", {}).values() if getattr(node, "high_value", False))
    extra_metadata = {
        "collector_stats": collector_reports,
        "high_value_count": high_value_count,
    }
    if diagnostics:
        extra_metadata["diagnostics"] = diagnostics

    output_path = None if args.validate_only else (outdir / "open_graph.json")
    export_data = export_graph(
        graph,
        output_path.as_posix() if output_path else None,
        mirror_bh_edges=True,
        collector_errors=collector_errors or None,
        extra_metadata=extra_metadata,
    )
    metadata = export_data.get("metadata", {})
    if output_path:
        LOG.info("[+] OpenGraph file written: %s", output_path)

    if args.validate_schema or args.validate_only:
        _validate_export_data(export_data)
        LOG.info("Schema validation passed")

    run_duration = perf_counter() - run_start

    # Print beautiful summary box
    print("\n" + "="*70)
    print("  COLLECTION SUMMARY")
    print("="*70)
    print(f"  Nodes:       {metadata.get('node_count', 0):>6,}")
    print(f"  Edges:       {metadata.get('edge_count', 0):>6,}")
    print(f"  High Value:  {metadata.get('high_value_count', high_value_count):>6,}")
    print(f"  Duration:    {run_duration:>6.2f}s")
    print(f"  Collectors:  {len(collector_reports):>6}")

    # Show collector success/failure
    successful = len(collector_reports) - len(collector_errors)
    if collector_errors:
        print(f"  Status:      {successful}/{len(collector_reports)} succeeded")
        print("\n  Failed collectors:")
        for err in collector_errors:
            print(f"    ✗ {err}")
    else:
        print(f"  Status:      ✓ All {len(collector_reports)} collectors succeeded")

    print("="*70)

    if args.validate_only:
        print("\n✓ Validation complete. Export file not written (--validate-only).\n")
        return

    print(f"\n✓ Export written: {output_path}\n")

    # Only print Cypher queries in debug mode
    if debug_mode:
        _print_post_ingest_queries()


def _generate_docs() -> None:
    model_path = Path("model.json")
    if not model_path.exists():
        print("model.json not found!")
        sys.exit(1)
    with model_path.open("r", encoding="utf-8") as handle:
        model = json.load(handle)
    doc = ["# AtlassianHound OpenGraph Model Documentation\n"]
    doc.append("## Node Types\n")
    for node in model.get("nodes", []):
        doc.append(f"- **{node['kind']}**: {node.get('label','')}  ")
        doc.append(f"  - Description: {node.get('description','')}")
        doc.append(f"  - Properties: {json.dumps(node.get('properties',{}) , indent=2)}\n")
    doc.append("\n## Edge Types\n")
    for edge in model.get("edges", []):
        doc.append(f"- **{edge['name']}**: {edge.get('label','')}  ")
        doc.append(f"  - Description: {edge.get('description','')}")
        doc.append(f"  - Properties: {json.dumps(edge.get('properties',{}), indent=2)}\n")
    doc.append("\n## Predefined Queries\n")
    for query in model.get("queries", []):
        doc.append(f"- **{query['name']}**: {query.get('description','')}  ")
        doc.append(f"  - Cypher: `{query.get('cypher','')}`\n")
    out_path = Path("atlassian_model_docs.md")
    out_path.write_text("\n".join(doc), encoding="utf-8")
    print(f"Documentation generated: {out_path}")


def _print_post_ingest_queries() -> None:
    model_path = Path("model.json")
    if not model_path.exists():
        return
    with model_path.open("r", encoding="utf-8") as handle:
        model = json.load(handle)
    LOG.info("Post-ingest Cypher queries (run manually in Neo4j):")
    for section in ("mirror_edges", "set_high_value"):
        for entry in model.get("post_ingest_cypher", {}).get(section, []):
            print(entry["cypher"])


def _execute_collector(
    label: str, func: Callable[[OpenGraph], None], graph: OpenGraph
) -> tuple[float, Optional[str]]:
    start = perf_counter()
    LOG.info("Starting %s collector...", label)
    try:
        func(graph)
    except Exception as exc:  # pragma: no cover
        LOG.exception("✗ %s collector failed", label)
        return 0.0, f"{label}: {exc}"
    duration = perf_counter() - start
    LOG.info("✓ %s completed in %.2fs", label, duration)
    return duration, None


def compute_enabled_collectors(settings: Dict[str, Iterable[str]]) -> List[str]:
    includes = settings.get("include")
    excludes = settings.get("exclude")
    if includes:
        requested = [c.strip() for c in includes if c.strip()]
    else:
        requested = list(DEFAULT_COLLECTORS)
    excluded = {c.strip().lower() for c in (excludes or []) if c}
    return [
        collector
        for collector in requested
        if collector and collector.lower() not in excluded and collector.lower() != "issues"
    ]


def _apply_http_settings(http_settings: Dict[str, object]) -> None:
    timeout = http_settings.get("timeout")
    if isinstance(timeout, (int, float)):
        common.API_TIMEOUT = int(timeout)


def _split_csv(value: str | Iterable[str]) -> List[str]:
    if isinstance(value, str):
        if not value:
            return []
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(item).strip() for item in value if str(item).strip()]


def _validate_export_data(data: Dict[str, Any]) -> None:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        print("Please install jsonschema: pip install jsonschema")
        sys.exit(1)
    schema_path = Path("model.json")
    if not schema_path.exists():
        LOG.warning("model.json missing; skipping schema validation.")
        return
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    jsonschema.validate(instance=data, schema=schema)


def _test_credentials() -> None:
    """Test Atlassian API credentials by calling the /myself endpoint."""
    from utils.http import get_session

    setup_logging(json_mode=False, level=logging.INFO)

    auth = common.get_auth()
    session = get_session()
    site_base = common.SITE_BASE

    if not site_base:
        LOG.error("ATLASSIAN_SITE_BASE not configured in environment")
        sys.exit(1)

    LOG.info("Testing credentials against %s...", site_base)

    try:
        resp = session.get(f"{site_base}/rest/api/3/myself", auth=auth, timeout=10)

        if resp.status_code == 200:
            user_info = resp.json()
            display_name = user_info.get("displayName", "Unknown")
            account_id = user_info.get("accountId", "Unknown")
            email = user_info.get("emailAddress", "N/A")
            LOG.info("✓ Credentials validated successfully!")
            LOG.info("  Authenticated as: %s (%s)", display_name, email)
            LOG.info("  Account ID: %s", account_id)
            sys.exit(0)
        elif resp.status_code == 401:
            LOG.error("✗ Authentication failed: Invalid credentials")
            LOG.error("  Check ATLASSIAN_EMAIL and ATLASSIAN_API_TOKEN in .env")
            sys.exit(1)
        elif resp.status_code == 403:
            LOG.error("✗ Authorization failed: Insufficient permissions")
            LOG.error("  API token may lack required scopes")
            sys.exit(1)
        else:
            LOG.error("✗ Unexpected response: HTTP %d", resp.status_code)
            LOG.error("  %s", resp.text[:200])
            sys.exit(1)

    except Exception as exc:
        LOG.exception("✗ Connection failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
