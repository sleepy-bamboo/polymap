from __future__ import annotations
import networkx as nx


def _entrypoint_style(entrypoint_type: str) -> dict:
    if entrypoint_type == "break-glass":
        return {"risk_level": "critical", "color": "#d64045", "weight": 3}
    if entrypoint_type == "sso":
        return {"risk_level": "elevated", "color": "#2f6f8f", "weight": 2}
    if entrypoint_type == "ci":
        return {"risk_level": "elevated", "color": "#2e7d32", "weight": 2}
    return {"risk_level": "unknown", "color": "#6b6b6b", "weight": 1}


def _bucket_style(meta: dict) -> dict:
    if meta.get("critical"):
        return {"risk_level": "critical", "color": "#d64045", "weight": 3}
    if meta.get("high_risk"):
        return {"risk_level": "high", "color": "#f2a900", "weight": 2}
    return {"risk_level": "normal", "color": "#8f8f8f", "weight": 1}


def _edge_style(perms: list[dict]) -> dict:
    verdicts = [p.get("verdict") for p in perms]
    if "DENIED" in verdicts:
        level = "denied"
        color = "#7a7a7a"
        weight = 1
    elif "AMBIGUOUS" in verdicts:
        level = "ambiguous"
        color = "#f2a900"
        weight = 2
    elif "ALLOWED" in verdicts:
        level = "allowed"
        color = "#d64045"
        weight = 3
    else:
        level = "none"
        color = "#b0b0b0"
        weight = 1
    return {
        "risk_level": level,
        "color": color,
        "weight": weight,
        "tag": level,
        "ambiguous": "AMBIGUOUS" in verdicts,
    }


def _apply_edge_style(g: nx.DiGraph, src: str, dst: str):
    perms = g[src][dst].get("permissions", [])
    g[src][dst].update(_edge_style(perms))

def build_graph(analysis: dict) -> nx.DiGraph:
    g = nx.DiGraph()

    # --- entrypoints ---
    for ep in analysis["entrypoints"]:
        kind = ep.get("kind", "principal")
        et = ep.get("entrypoint_type", "unknown")
        name = ep.get("name", ep.get("arn", "unknown"))
        label = f"{name} ({kind})"
        style = _entrypoint_style(et)

        g.add_node(
            ep["arn"],
            type="entrypoint",
            label=label,
            entrypoint_type=et,
            principal_kind=kind,
            principal_name=name,
            tag=et,
            color=style["color"],
            weight=style["weight"],
            risk_level=style["risk_level"],
        )

    # --- roles (intermediate nodes) ---
    # Important: some roles are also entrypoints; don't overwrite type=entrypoint if already present.
    for r in analysis.get("roles", []):
        arn = r["arn"]
        if g.has_node(arn):
            # keep entrypoint node, but add role attributes
            g.nodes[arn]["is_role"] = True
            continue

        g.add_node(
            arn,
            type="role",
            label=f"{r.get('name', arn)} (role)",
            principal_kind="role",
            principal_name=r.get("name", arn),
            tag="role",
            color="#6b6b6b",
            weight=1,
            risk_level="normal",
        )

    # --- buckets (only critical/high-risk) ---
    wanted = {b["name"]: b for b in analysis["buckets"] if b["critical"] or b["high_risk"]}
    for name, meta in wanted.items():
        nid = f"s3::{name}"
        if meta["critical"]:
            bucket_kind = "critical"
        elif meta["high_risk"]:
            bucket_kind = "high-risk"
        else:
            bucket_kind = "bucket"
        style = _bucket_style(meta)

        g.add_node(
            nid,
            type="s3_bucket",
            bucket_kind=bucket_kind,
            label=name,
            critical=bool(meta["critical"]),
            high_risk=bool(meta["high_risk"]),
            risk_signals=meta.get("risk_signals") or [],
            tag=bucket_kind,
            color=style["color"],
            weight=style["weight"],
            risk_level=style["risk_level"],
        )

    # --- edges: assume-role ---
    for e in analysis.get("assume_role", []):
        src = e["source_arn"]
        dst = e["target_role_arn"]
        verdict = e["verdict"]

        g.add_edge(
            src,
            dst,
            edge_type="assume-role",
            permissions=[{"action": "sts:AssumeRole", "resource": dst, "verdict": verdict}],
            details=e.get("details", {}),
        )
        _apply_edge_style(g, src, dst)

    # --- edges: direct access from entrypoints to buckets ---
    for row in analysis.get("access", []):
        src = row["principal_arn"]
        dst = f"s3::{row['bucket']}"
        _add_permission_edge(g, src, dst, row["matches"], edge_type="access")

    # --- edges: role access to buckets (for chaining) ---
    for row in analysis.get("role_access", []):
        src = row["principal_arn"]
        dst = f"s3::{row['bucket']}"
        _add_permission_edge(g, src, dst, row["matches"], edge_type="access")

    return g

def _add_permission_edge(g: nx.DiGraph, src: str, dst: str, matches: list[dict], edge_type: str):
    if g.has_edge(src, dst):
        # fold permissions into list
        g[src][dst]["permissions"].extend(matches)
    else:
        g.add_edge(src, dst, edge_type=edge_type, permissions=list(matches))
    _apply_edge_style(g, src, dst)
