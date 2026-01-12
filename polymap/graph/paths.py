from __future__ import annotations
import networkx as nx

def _permission_score(perms: list[dict]) -> int:
    score = 0
    for p in perms:
        v = p.get("verdict")
        if v == "ALLOWED":
            score += 5
        elif v == "AMBIGUOUS":
            score += 2
        elif v == "DENIED":
            score -= 10
    return score

def _bucket_risk_score(node_attrs: dict) -> int:
    score = 0
    if node_attrs.get("critical"):
        score += 6
    if node_attrs.get("high_risk"):
        score += 4
    score += min(6, len(node_attrs.get("risk_signals") or []))
    return score

def find_and_rank_paths(g: nx.DiGraph, analysis: dict, max_results: int = 80) -> dict:
    entrypoints = [n for n, a in g.nodes(data=True) if a.get("type") == "entrypoint"]
    buckets = [n for n, a in g.nodes(data=True) if a.get("type") == "s3_bucket"]

    paths = []
    # allow multi-hop: entrypoint -> role -> bucket (and maybe more later)
    cutoff = 5

    for ep in entrypoints:
        for b in buckets:
            if not nx.has_path(g, ep, b):
                continue

            for pth in nx.all_simple_paths(g, ep, b, cutoff=cutoff):
                score = 0

                # sum edge permission scores along the path
                for i in range(len(pth) - 1):
                    u, v = pth[i], pth[i+1]
                    if g.has_edge(u, v):
                        perms = g[u][v].get("permissions", [])
                        score += _permission_score(perms)
                        # small bonus for having assume-role in path (because it's a real chain)
                        if g[u][v].get("edge_type") == "assume-role":
                            score += 1

                # bucket risk score
                score += _bucket_risk_score(g.nodes[b])

                # shorter is better
                hops = len(pth) - 1
                score += max(0, 6 - hops)

                paths.append({"path": pth, "score": score})

    paths.sort(key=lambda x: x["score"], reverse=True)
    paths = paths[:max_results]

    bucket_summary = []
    for b in buckets:
        a = g.nodes[b]
        bucket_summary.append({
            "bucket": a.get("label"),
            "critical": bool(a.get("critical")),
            "high_risk": bool(a.get("high_risk")),
            "risk_signals": a.get("risk_signals") or [],
        })

    return {
        "top_paths": paths,
        "bucket_summary": bucket_summary,
        "notes": analysis.get("notes", []),
    }
