
from __future__ import annotations

import json
from pathlib import Path
import typer

from polymap.aws.session import make_session, collect_s3
from polymap.aws.iam_collector import collect_iam
from polymap.policy.effective import analyze_access
from polymap.graph.build import build_graph
from polymap.graph.paths import find_and_rank_paths
from polymap.graph.export import export_graph_json
from polymap.web.app import run

app = typer.Typer(add_completion=False)

@app.command()
def scan(
    profile: str = typer.Option(None, help="AWS profile name"),
    region: str = typer.Option("us-east-1", help="AWS region (IAM global; S3 mostly global)"),
    out_dir: Path = typer.Option(Path("./out"), help="Output directory"),
    strict_ambiguous: bool = typer.Option(False, "--strict-ambiguous", help="Keep AMBIGUOUS verdicts instead of treating them as ALLOWED"),
):
    out_dir.mkdir(parents=True, exist_ok=True)

    sess_and_cfg = make_session(profile=profile, region=region)

    iam_data = collect_iam(sess_and_cfg)
    s3_data = collect_s3(sess_and_cfg)

    (out_dir / "iam.json").write_text(json.dumps(iam_data, indent=2, default=str), encoding="utf-8")
    (out_dir / "s3.json").write_text(json.dumps(s3_data, indent=2, default=str), encoding="utf-8")

    analysis = analyze_access(iam_data, s3_data, ambiguous_as_allowed=not strict_ambiguous)
    (out_dir / "analysis.json").write_text(json.dumps(analysis, indent=2, default=str), encoding="utf-8")

    g = build_graph(analysis)
    export_graph_json(g, out_dir / "graph.json")

    report = find_and_rank_paths(g, analysis)
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    typer.echo(f"Done. Results in: {out_dir}")

@app.command()
def serve(
    out_dir: Path = typer.Option(Path("./out"), help="Directory containing graph.json and report.json"),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8082),
):
    run(out_dir=out_dir, host=host, port=port)

if __name__ == "__main__":
    app()
