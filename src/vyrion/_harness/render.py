"""Render a FrameworkReport to Markdown and JSON.

The Markdown is the human-facing attack-surface pack: the discovered chain with
source evidence, then one section per technique with the concrete points, the
payload an attacker writes, why it works today, and the Seal binding that closes
it. The JSON is the machine artifact used later to fold in live-runtime proofs.
"""

from __future__ import annotations

import json
from .model import FrameworkReport, Technique

_TECH_ORDER = [Technique.FORGE, Technique.REBIND, Technique.REPLAY,
               Technique.SUPPRESS, Technique.LAUNDER]


def to_json(report: FrameworkReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def _ev_line(ev) -> str:
    if not ev:
        return "  no direct source evidence (inferred from framework contract)"
    return (f"  `{ev.path}:{ev.start_line}` ({ev.construct}, via {ev.parser})\n"
            f"  ```{ev.language}\n  {ev.snippet.strip()}\n  ```")


def to_markdown(report: FrameworkReport) -> str:
    r = report
    L = []
    L.append(f"# HITL Attack-Surface Pack: {r.framework}")
    L.append("")
    L.append(f"- Category: {r.category}")
    L.append(f"- Target project: `{r.target_project}`")
    L.append(f"- Detected: {'yes' if r.detected else 'no'}  |  Version: {r.version}")
    if r.ledger_verdicts:
        v = ", ".join(f"{k} {val}" for k, val in r.ledger_verdicts.items())
        L.append(f"- Research ledger verdicts: {v}")
    L.append("")
    L.append("This pack lists every point at which each of the five provenance "
             "techniques could land in this project, with source evidence, the "
             "attacker payload, and the binding that closes it. The live-runtime "
             "proof is produced separately and folded in to reach Native Certified.")
    L.append("")

    if not r.chains:
        L.append("No HITL approval chain was discovered. " + " ".join(r.notes))
        return "\n".join(L)

    L.append("## Discovered approval-to-action chains")
    L.append("")
    for i, c in enumerate(r.chains, 1):
        L.append(f"### Chain {i}: {c.approval.id} -> {c.action.id}")
        L.append("")
        L.append(f"**Approval point** ({c.approval.mechanism})")
        L.append(_ev_line(c.approval.evidence))
        L.append("")
        L.append(f"**Persistence boundary**: {c.persistence.mechanism}, "
                 f"decision at `{c.persistence.marker_path}`  |  "
                 f"**Resume**: {c.resume_mechanism}")
        L.append("")
        L.append(f"**Protected action**: `{c.action.id}` ({c.action.kind}), "
                 f"arguments: {', '.join(c.action.arguments) or 'n/a'}")
        L.append(_ev_line(c.action.evidence))
        L.append("")

    L.append("## Five-technique attack surface")
    L.append("")
    surf_by_tech = {s.technique: s for s in r.surfaces}
    for tech in _TECH_ORDER:
        s = surf_by_tech.get(tech)
        if not s:
            continue
        status = "APPLICABLE" if s.applicable else "RESISTANT"
        L.append(f"### {tech.value}  [{status}]")
        L.append("")
        L.append(s.rationale)
        L.append("")
        if not s.applicable:
            L.append("_This framework resists this technique; no landing point._")
            L.append("")
            continue
        for j, p in enumerate(s.points, 1):
            L.append(f"**Point {j}: `{p.location}`**")
            if p.evidence:
                L.append(_ev_line(p.evidence))
            L.append(f"- Attacker writes: {p.attacker_writes}")
            L.append(f"- Why it works today: {p.why_it_works}")
            L.append(f"- Binding that defeats it: {p.binding_that_defeats_it}")
            L.append("")

    L.append("## Live-proof runbook")
    L.append("")
    L.append("To promote this framework to Native Certified, run each technique "
             "against the real installed framework at the point above and capture "
             "the transcript:")
    L.append("")
    L.append("1. Start the real workflow and reach the approval point.")
    L.append("2. For Forge/Launder: write the approve marker into the real store; "
             "confirm the action executes and the audit names an approver who never approved.")
    L.append("3. For Rebind: approve, then mutate the persisted action/arguments; "
             "confirm the changed action executes.")
    L.append("4. For Replay: reuse a genuine approval in a second run/checkpoint; "
             "confirm it is accepted twice.")
    L.append("5. For Suppress: advance past the gate without a human prompt; "
             "confirm the action executes.")
    L.append("6. Save stdout/stderr as the runtime transcript and return it for folding.")
    L.append("")
    return "\n".join(L)
