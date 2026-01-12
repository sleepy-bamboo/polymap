"""Graph export helpers."""

from __future__ import annotations

import json
from pathlib import Path
from networkx.readwrite import json_graph


def export_graph(graph, fmt: str = "json"):
    """Export graph data in the requested format."""
    if fmt == "json":
        return json_graph.node_link_data(graph)
    raise ValueError(f"unsupported format: {fmt}")


def export_graph_json(graph, out_path: Path):
    data = export_graph(graph, fmt="json")
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
