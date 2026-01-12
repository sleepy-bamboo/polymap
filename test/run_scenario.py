from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from polymap.policy.effective import analyze_access
from polymap.graph.build import build_graph
from polymap.graph.export import export_graph_json
from polymap.graph.paths import find_and_rank_paths

SCENARIO = 3  # set 1, 2, or 3


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=int, default=SCENARIO, choices=[1, 2, 3, 4])
    parser.add_argument(
        "--strict-ambiguous",
        action="store_true",
        help="Keep AMBIGUOUS verdicts instead of treating them as ALLOWED",
    )
    args = parser.parse_args()

    scenario = args.scenario
    ambiguous_as_allowed = not args.strict_ambiguous

    base = Path(__file__).resolve().parent
    iam_path = base / f"iam_scenario{scenario}.json"
    s3_path = base / f"s3_scenario{scenario}.json"

    if not iam_path.exists() or not s3_path.exists():
        raise SystemExit(f"Missing scenario files: {iam_path} {s3_path}")

    iam = json.loads(iam_path.read_text(encoding="utf-8"))
    s3 = json.loads(s3_path.read_text(encoding="utf-8"))

    analysis = analyze_access(iam, s3, ambiguous_as_allowed=ambiguous_as_allowed)

    out_dir = base.parent / f"out_scenario{scenario}"
    out_dir.mkdir(exist_ok=True)

    (out_dir / "analysis.json").write_text(
        json.dumps(analysis, indent=2, default=str), encoding="utf-8"
    )
    g = build_graph(analysis)
    export_graph_json(g, out_dir / "graph.json")
    report = find_and_rank_paths(g, analysis)
    (out_dir / "report.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )

    print(f"ok: {out_dir}")
    print(f"serve: python -m polymap.cli serve --out-dir {out_dir}")


if __name__ == "__main__":
    main()
