from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, Set

from bhopengraph.Edge import Edge
from bhopengraph.OpenGraph import OpenGraph


def run_diagnostics(graph: OpenGraph) -> Dict[str, int]:
    nodes = getattr(graph, "nodes", {})
    edges: Iterable[Edge] = getattr(graph, "edges", [])

    node_ids: Set[str] = set(nodes.keys())
    referenced_nodes: Set[str] = set()
    duplicate_edges = 0
    dangling_edges = 0

    edge_counter: Counter[str] = Counter()

    for edge in edges:
        start = getattr(edge, "start_node", None)
        end = getattr(edge, "end_node", None)
        if start:
            referenced_nodes.add(start)
        if end:
            referenced_nodes.add(end)

        if not start or not end or start not in node_ids or end not in node_ids:
            dangling_edges += 1

        edge_counter[edge.get_unique_id()] += 1

    duplicate_edges = sum(count - 1 for count in edge_counter.values() if count > 1)
    orphan_nodes = len(node_ids - referenced_nodes)

    return {
        "node_total": len(node_ids),
        "edge_total": sum(edge_counter.values()),
        "orphan_nodes": orphan_nodes,
        "dangling_edges": dangling_edges,
        "duplicate_edges": duplicate_edges,
    }
