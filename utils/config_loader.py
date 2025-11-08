from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

try:  # Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore

try:  # Optional dependency
    import yaml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    yaml = None  # type: ignore


DEFAULT_CONFIG_FILENAMES = (
    ".atlassianhound.toml",
    ".atlassianhound.yaml",
    ".atlassianhound.yml",
)


def _load_toml(path: Path) -> Dict[str, Any]:
    if not tomllib:
        raise RuntimeError("tomllib not available; cannot parse TOML configuration.")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not yaml:
        raise RuntimeError("PyYAML not installed; cannot parse YAML configuration.")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return data or {}


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load AtlassianHound configuration.

    Search order:
    1. Explicit config_path (if provided)
    2. .atlassianhound.(toml|yaml|yml) in current working directory
    """
    candidates: list[Path] = []
    if config_path:
        candidates.append(Path(config_path))
    else:
        cwd = Path(os.getcwd())
        candidates.extend(cwd / name for name in DEFAULT_CONFIG_FILENAMES)

    for candidate in candidates:
        if not candidate.exists():
            continue
        suffix = candidate.suffix.lower()
        try:
            if suffix == ".toml":
                return _load_toml(candidate)
            if suffix in (".yaml", ".yml"):
                return _load_yaml(candidate)
        except Exception as exc:  # pragma: no cover - surface parsing problems
            raise RuntimeError(f"Failed to parse configuration file {candidate}: {exc}") from exc

    return {}


def merge_settings(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge overlay into base, returning a new dict.
    """
    result = dict(base)
    for key, value in overlay.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = merge_settings(result[key], value)
        else:
            result[key] = value
    return result
