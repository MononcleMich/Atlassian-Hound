from __future__ import annotations

from utils.bhcompat import ensure_environment_root as _ensure_root
from utils.bhcompat import link_node_to_environment as _link


def ensure_environment_root(graph) -> str:
    return _ensure_root(graph)


def link_node_to_environment(graph, node_id: str) -> None:
    _link(graph, node_id)
