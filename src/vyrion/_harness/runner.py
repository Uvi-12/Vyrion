"""Run every harness and write per-framework reports plus a fleet index."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .registry import ALL_HARNESSES
from .render import to_json, to_markdown


def run_fleet(out_dir: str = "reports", project_override: str | None = None) -> dict:
    out = Path(out_dir)
    (out / "frameworks").mkdir(parents=True, exist_ok=True)
    index = {"frameworks": [], "totals": {"detected": 0, "with_chain": 0,
             "applicable_points": 0}}
    for h in ALL_HARNESSES:
        report = h.run(project_override)
        slug = h.name.lower().replace(" ", "_")
        (out / "frameworks" / f"{slug}.md").write_text(to_markdown(report))
        (out / "frameworks" / f"{slug}.json").write_text(to_json(report))
        pts = sum(len(s.points) for s in report.surfaces if s.applicable)
        applicable = sum(1 for s in report.surfaces if s.applicable)
        index["frameworks"].append({
            "framework": report.framework, "category": report.category,
            "detected": report.detected, "version": report.version,
            "chains": len(report.chains),
            "applicable_techniques": applicable,
            "surface_points": pts,
            "report_md": f"frameworks/{slug}.md",
            "report_json": f"frameworks/{slug}.json",
        })
        index["totals"]["detected"] += 1 if report.detected else 0
        index["totals"]["with_chain"] += 1 if report.chains else 0
        index["totals"]["applicable_points"] += pts
    (out / "index.json").write_text(json.dumps(index, indent=2))
    _write_summary(out, index)
    return index


def _write_summary(out: Path, index: dict):
    L = ["# Vyrion HITL Attack-Surface Reports", "",
         f"Frameworks analyzed: {len(index['frameworks'])}  |  "
         f"detected: {index['totals']['detected']}  |  "
         f"with discovered chain: {index['totals']['with_chain']}  |  "
         f"total applicable surface points: {index['totals']['applicable_points']}", "",
         "Each framework below is EXPOSED and native-verified across the five "
         "techniques in the research ledgers. This run discovers the real approval "
         "chain in each target project and maps the five-technique attack surface "
         "onto it. Live-runtime proofs are folded in separately to reach Native "
         "Certified.", "",
         "| Framework | Category | Detected | Chains | Applicable techniques | Surface points | Report |",
         "|---|---|---|---|---|---|---|"]
    for f in index["frameworks"]:
        L.append(f"| {f['framework']} | {f['category']} | "
                 f"{'yes' if f['detected'] else 'no'} | {f['chains']} | "
                 f"{f['applicable_techniques']}/5 | {f['surface_points']} | "
                 f"[md]({f['report_md']}) |")
    (out / "README.md").write_text("\n".join(L) + "\n")
