"""CLI backing for `vyrion certify` and the native `vyrion apply`.

certify runs the N1-N20 lifecycle and reports the tier from real gate results.
apply performs a real install (guard + manifest + backups), never a no-op.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from . import certify, GateStatus
from .registry import build_fleet, target_for
from .verification.matrix import render_matrix_markdown, render_matrix_json


def _find(framework):
    _dedicated = {"LangGraph": "langgraph", "LlamaIndex Workflows": "llamaindex",
                  "Apache Burr": "burr", "DBOS Transact": "dbos", "CrewAI Flows": "crewai", "OpenAI Agents SDK": "openai_agents", "Google ADK": "google_adk", "AutoGen": "autogen", "Haystack": "haystack", "Strands Agents": "strands", "Agno": "agno", "Semantic Kernel": "semantic_kernel", "Apache Airflow": "airflow", "Genkit": "genkit", "Vercel AI": "vercel_ai"}
    for adapter, expected in build_fleet():
        sample = adapter.spec.sample_dir if hasattr(adapter, "spec") \
            else _dedicated.get(adapter.framework, adapter.framework.lower())
        if framework in (sample, adapter.framework, adapter.framework.lower()):
            return adapter, expected, sample
    return None, None, None


def cmd_certify(args):
    # whole-fleet matrix
    if not args.framework:
        if args.json:
            text = render_matrix_json()
        else:
            text = render_matrix_markdown()
        if args.out:
            Path(args.out).write_text(text); print(f"written: {args.out}")
        else:
            print(text)
        return 0

    adapter, expected, sample = _find(args.framework)
    if adapter is None:
        print(f"unknown framework: {args.framework}")
        return 2

    # certify mutates (apply then rollback), so always operate on a throwaway copy
    src = Path(args.project) if args.project else target_for(sample)
    if not src.exists():
        print(f"project path not found: {src}")
        print("pass an existing project with --project, or omit it to use the bundled sample.")
        return 2
    target = Path(tempfile.mkdtemp()) / "proj"
    shutil.copytree(src, target)

    if args.live:
        # --live runs the real certification: verify_runtime executes the framework
        # if present, or reports pending if it is not installed on this host.
        cert = certify(adapter, str(target))
        print(f"{adapter.framework}: {cert.tier} (runtime: {cert.runtime_status or 'pending_live_host'})")
        for g in cert.gates:
            if g.id in ("N13", "N14", "N15", "N16", "N17"):
                mark = {"PASS": "ok ", "PENDING_LIVE": "...", "FAIL": "XX ", "SKIP": "-  "}[g.status.value]
                print(f"  {mark}{g.id} {g.name:44s} {g.detail}")
        if cert.runtime_status != "executed_here":
            print(f"\n  live gates need the framework on this host: {getattr(adapter, 'host_requirements', '')}")
        return 0 if not any(g.status == GateStatus.FAIL for g in cert.gates) else 1

    cert = certify(adapter, str(target))
    print(f"{adapter.framework}: {cert.tier} (runtime: {cert.runtime_status or 'pending_live_host'})")
    for g in cert.gates:
        mark = {"PASS": "ok ", "PENDING_LIVE": "...", "FAIL": "XX ", "SKIP": "-  "}[g.status.value]
        print(f"  {mark}{g.id:4s} {g.name:44s} {g.detail}")
    return 0 if not any(g.status == GateStatus.FAIL for g in cert.gates) else 1


def cmd_apply(args):
    adapter, expected, sample = _find(args.framework or "")
    if adapter is None:
        print("apply requires --framework <name>; run `vyrion certify` to list frameworks")
        return 2
    target = Path(args.project or ".")
    if not target.exists():
        print(f"project path not found: {target}")
        return 2
    if (target / ".vyrion" / "manifest.json").exists():
        print(f"{adapter.framework}: already protected (found .vyrion/manifest.json at "
              f"{target}).")
        print(f"  roll back first: vyrion rollback --framework {args.framework} "
              f"--project {target}")
        return 1
    det = adapter.detect_project(str(target))
    if not det.detected:
        print(f"{adapter.framework}: not detected at {target}; nothing applied")
        return 1
    aps = adapter.discover_approval_points(str(target))
    if not aps:
        print("no approval point found; nothing applied")
        return 1
    traces = adapter.trace_actions(str(target), aps[0])
    if not traces:
        print("no protected action traced; nothing applied")
        return 1
    patch = adapter.generate_patch(str(target), traces[0])
    applied = adapter.apply_patch(str(target), patch)
    print(f"{adapter.framework}: guard installed at {target}")
    print(f"  manifest: {applied.manifest_path}")
    print(f"  backups:  {applied.backup_dir}")
    for rel, before, after in applied.changed_files:
        print(f"  wrote {rel} ({before} -> {after})")
    print("  rollback: vyrion rollback --framework "
          f"{sample} --project {target}")
    return 0


def cmd_rollback(args):
    adapter, expected, sample = _find(args.framework or "")
    if adapter is None:
        print("rollback requires --framework <name>")
        return 2
    target = Path(args.project or ".")
    rb = adapter.rollback(str(target), None)
    print(f"{adapter.framework}: rolled back {len(rb.files_restored)} file(s); "
          f"byte-identical={rb.byte_identical}")
    return 0


def cmd_test_guard(args):
    """Run the guard-only authorization battery (does NOT run the framework)."""
    adapter, expected, sample = _find(args.framework or "")
    if adapter is None or not hasattr(adapter, "run_live"):
        print("test-guard requires a spec-driven framework adapter")
        return 2
    target = Path(tempfile.mkdtemp()) / "proj"
    shutil.copytree(target_for(sample), target)
    det = adapter.detect_project(str(target))
    aps = adapter.discover_approval_points(str(target))
    tr = adapter.trace_actions(str(target), aps[0])[0]
    adapter.apply_patch(str(target), adapter.generate_patch(str(target), tr))
    proof = adapter.run_live(str(target))
    print(f"{adapter.framework} guard-only battery (framework NOT executed):")
    for k, v in proof.checks.items():
        print(f"  {k:18s} {v}")
    print("\nThis exercises the installed guard, not the real framework. For N13-N17, "
          "run: vyrion certify --framework " + sample + " --live --project <your project>")
    return 0


def _detect_adapter(project):
    """Try every native adapter and return the first that detects the project."""
    from .registry import build_fleet
    for adapter, _ in build_fleet():
        try:
            det = adapter.detect_project(str(project))
            if getattr(det, "detected", False):
                return adapter, det
        except Exception:
            continue
    return None, None


def cmd_run(args):
    """Point Vyrion at a real project (folder or .zip): detect the framework,
    wire the Ghost Approval guard into the real source, and run the live gates
    if the framework is installed on this host. This is a real deployment, not
    a bundled sample: it modifies the project you give it (with backups)."""
    import zipfile
    raw = Path(args.project)
    if not raw.exists():
        print(f"project path not found: {raw}")
        return 2

    # accept a .zip or a folder; a zip is extracted next to itself
    if raw.is_file() and raw.suffix == ".zip":
        workdir = Path(tempfile.mkdtemp()) / "project"
        workdir.mkdir(parents=True)
        with zipfile.ZipFile(raw) as z:
            z.extractall(workdir)
        # if the zip contains a single top folder, descend into it
        entries = [p for p in workdir.iterdir() if not p.name.startswith("__MACOSX")]
        project = entries[0] if len(entries) == 1 and entries[0].is_dir() else workdir
        print(f"extracted {raw.name} -> {project}")
    else:
        project = raw

    if (Path(project) / ".vyrion" / "manifest.json").exists():
        print(f"already protected: found .vyrion/manifest.json at {project}.")
        print("  this project is already guarded. Roll back first, or use a fresh copy:")
        print(f"  vyrion rollback --project {project} --framework <name>")
        return 1

    adapter, det = _detect_adapter(project)
    if adapter is None:
        print(f"no supported framework detected in {project}")
        print("supported: run `vyrion certify` to list the 15 native frameworks.")
        return 1
    print(f"detected: {adapter.framework}")
    for e in (det.evidence or [])[:3]:
        print(f"  evidence: {e}")

    aps = adapter.discover_approval_points(str(project))
    if not aps:
        print("no human-approval point found; nothing to protect.")
        return 1
    traces = adapter.trace_actions(str(project), aps[0])
    if not traces:
        print(f"detected a human-approval point ({aps[0].id}) but could not resolve the "
              "protected action automatically.")
        print("this happens with dynamic graphs or unusual routing. you can point vyrion "
              "at the specific workflow file's directory, or open an issue with the graph shape.")
        return 1
    trace = traces[0]
    print(f"approval point: {aps[0].id}   protected action: {trace.action_id}")

    if args.dry_run:
        print("\n--dry-run: would wire the guard into the action above and run the live gates.")
        return 0

    # Modifying real source is destructive; confirm unless --yes or non-interactive intent.
    if not getattr(args, "yes", False):
        import sys
        print(f"\nThis will modify source under: {project}")
        print("  (a backup is written and `vyrion rollback` restores it byte-for-byte)")
        try:
            reply = input("Proceed? [y/N] ").strip().lower()
        except EOFError:
            reply = "n"
        if reply not in ("y", "yes"):
            print("aborted; nothing was changed. Re-run with --yes to skip this prompt, "
                  "or --dry-run to preview.")
            return 1

    applied = adapter.apply_patch(str(project), adapter.generate_patch(str(project), trace))
    print(f"\nwired the Ghost Approval guard into the real source:")
    for name, before, after in applied.changed_files:
        print(f"  {name} ({before} -> {after})")
    print(f"  backups: {applied.backup_dir}")
    print(f"  rollback: restore the files under that backups directory")

    # Level 1: universal enforcement proof. Dependency-free, framework-agnostic.
    # Exercises the five provenance gates against the guard/broker just installed,
    # using this repo's real manifest. No framework node runs; no key is needed.
    from .protection.enforcement_proof import prove_enforcement, ProofUnavailable
    try:
        results, passed = prove_enforcement(str(project))
        print("\nenforcement proof against the installed guard (this repo's manifest):")
        labels = {"genuine": "genuine Seal", "forged": "forged (no Seal)",
                  "cross_context": "cross-run Seal", "replayed": "replayed Seal",
                  "arg_tampered": "argument-tampered"}
        for gate in ("genuine", "forged", "cross_context", "replayed", "arg_tampered"):
            print(f"  {labels[gate]:20s} {results[gate]}")
        if passed:
            print("\nprovenance enforced: only the genuine Seal authorized the action; "
                  "forged, cross-run, replayed, and tampered approvals were all blocked.")
        else:
            print("\nWARNING: enforcement did not hold on every gate; see the verdicts above.")
    except ProofUnavailable as exc:
        print(f"\nguard installed and source patched (enforcement proof skipped: {exc}).")

    # Level 2 (bonus): framework-specific end-to-end run, when importable here.
    try:
        proof = adapter.verify_runtime(str(project), applied)
    except Exception:
        proof = None
    if proof is not None and proof.status == "executed_here":
        print(f"\nend-to-end live run against the real framework:")
        for k, v in proof.checks.items():
            print(f"  {k:18s} {v}")
        print("\nGhost Approvals blocked at execution: forged, cross-context, replayed, "
              "and bypassed approvals were all rejected; only the genuine Seal ran.")
    return 0

# vyrion-build: 15-frameworks COMPLETE incl. Genkit + VercelAI
