"""Native adapter for Apache Burr.

Burr persists application State; a human-approval step writes the decision into
that State and the protected @action reads it back on resume. Any writer of the
persisted State can set the approval (the Ghost Approval surface). This adapter
finds the real protected @action, wires a fail-closed Seal guard into it, and
runs the modified app against the real Burr runtime.
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
import shutil
import sys
from pathlib import Path

from ..protection.templates import GUARD_MODULE, BROKER_MODULE
from ..protection.patcher import patch_burr
from ..contract import (ActionTrace, AppliedPatch, ApprovalPointEvidence,
                        BindingAnalysis, DetectionEvidence, NativeAdapter,
                        PatchPlan, PersistenceEvidence, RescanEvidence, ResumeEvidence,
                        RollbackEvidence, RuntimeProof, SourceEvidence)


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()[:16]


class BurrNativeAdapter(NativeAdapter):
    framework = "Apache Burr"
    native_package = "vyrion-burr"
    host_requirements = "pip install burr"

    def _py_files(self, project):
        # Deterministic across operating systems and filesystems: os.walk order
        # is not stable, so collect every .py path and yield them sorted.
        skip = {".vyrion", ".git", "__pycache__", ".venv", "venv",
                "node_modules", ".mypy_cache", ".pytest_cache", "build", "dist"}
        matches = []
        for root, dirs, files in os.walk(project):
            dirs[:] = [d for d in dirs if d not in skip]
            if ".vyrion" in root:
                continue
            for f in files:
                if f.endswith(".py"):
                    matches.append(os.path.join(root, f))
        yield from sorted(matches)

    def _ev(self, path, node, text, construct):
        s = getattr(node, "lineno", 1)
        e = getattr(node, "end_lineno", s)
        line = text.splitlines()[s - 1].strip() if text.splitlines() else ""
        return SourceEvidence(path=path, start_line=s, end_line=e, language="python",
                              construct=construct, snippet=line, parser="python-ast",
                              fingerprint=_sha(line), confidence="high")

    # ---- N1: detection
    def detect_project(self, project):
        hits = []
        for path in self._py_files(project):
            text = Path(path).read_text()
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("burr"):
                    hits.append(self._ev(path, n, text, "burr import"))
        return DetectionEvidence(detected=bool(hits), framework=self.framework, evidence=hits)

    # ---- N2
    def detect_version(self, project):
        try:
            import importlib.metadata as m
            return m.version("burr")
        except Exception:
            return "unknown"

    def _actions(self, project):
        """Return {func_name: (path, text, node, reads, writes)} for every @action."""
        found = {}
        for path in self._py_files(project):
            text = Path(path).read_text()
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in n.decorator_list:
                        name = dec.func.id if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) \
                            else (dec.id if isinstance(dec, ast.Name) else None)
                        if name == "action":
                            reads, writes = [], []
                            if isinstance(dec, ast.Call):
                                for kw in dec.keywords:
                                    vals = [e.value for e in kw.value.elts] if isinstance(kw.value, ast.List) else []
                                    if kw.arg == "reads":
                                        reads = [v for v in vals if isinstance(v, str)]
                                    if kw.arg == "writes":
                                        writes = [v for v in vals if isinstance(v, str)]
                            found[n.name] = (path, text, n, reads, writes)
        return found

    # ---- N3: the human-approval action (writes "approval")
    def discover_approval_points(self, project):
        for name, (path, text, node, reads, writes) in self._actions(project).items():
            if "approval" in writes:
                return [ApprovalPointEvidence(
                    id="burr-approval", mechanism="@action human-approval step (persisted State)",
                    evidence=self._ev(path, node, text, f"@action {name}()"))]
        # fallback: any action whose name suggests approval
        for name, (path, text, node, reads, writes) in self._actions(project).items():
            if "approv" in name.lower():
                return [ApprovalPointEvidence("burr-approval", "@action approval step",
                                              self._ev(path, node, text, f"@action {name}()"))]
        return []

    # ---- N4/N5
    def discover_persistence(self, project):
        return [PersistenceEvidence("Burr persisted application State",
                                    "state.approval", True)]

    def discover_resume(self, project):
        return [ResumeEvidence("app.run(halt_before=[...]) / update_state / app.run(halt_after=[...])")]

    # ---- N6/N7: the protected action (reads "approval", not the approval-setter)
    def _protected(self, project):
        acts = self._actions(project)
        setters = {n for n, (_, _, _, _, w) in acts.items() if "approval" in w}
        # fields written by the approval action mutate across the boundary; exclude them
        approval_writes = set()
        for n in setters:
            approval_writes |= set(acts[n][4])
        for name, (path, text, node, reads, writes) in acts.items():
            if name in setters:
                continue
            if "approval" in reads or "executed" in writes:
                control = {"approval", "seal", "_vyrion_run", "_vyrion_cp", "executed"}
                fields = [r for r in reads if r not in control and r not in approval_writes]
                return name, path, text, node, (fields or ["amount"])
        return None

    def trace_actions(self, project, approval):
        p = self._protected(project)
        if not p:
            return []
        name, path, text, node, fields = p
        tr = ActionTrace(approval.id, f"action.{name}", "burr @action",
                         fields, ["approval"] + fields,
                         self._ev(path, node, text, f"@action {name}()"))
        tr.action_func = name
        tr.source_rel = os.path.relpath(path, project)
        return [tr]

    def analyze_bindings(self, trace):
        return BindingAnalysis(missing=["approver_authenticated", "action_bound",
            "arguments_bound", "run_bound", "checkpoint_bound", "replay_protected",
            "verified_at_execution"])

    # ---- N8
    def generate_patch(self, project, trace):
        fp = _sha(trace.evidence.snippet)
        manifest = {"schema": "vyrion.manifest.v1", "framework": "burr",
                    "approval_point": trace.approval_id, "action_id": trace.action_id,
                    "action_fingerprint": fp, "environment": "production",
                    "audience": "payments", "tenant": "default", "fail_mode": "closed",
                    "public_keys": "public-keys/",
                    "source_file": getattr(trace, "source_rel", "payment_app.py")}
        plan = PatchPlan(
            steps=["back up the protected source",
                   "patch source: wire the guard into the protected @action",
                   "install vyrion_guard.py", "create .vyrion/manifest.json"],
            files_touched=[getattr(trace, "source_rel", "payment_app.py")],
            generated_artifacts={"vyrion_guard.py": GUARD_MODULE,
                                 "vyrion_broker.py": BROKER_MODULE,
                                 ".vyrion/manifest.json": json.dumps(manifest, indent=2)},
            native_package=self.native_package)
        plan.action_fingerprint = fp
        plan.action_func = getattr(trace, "action_func", "transfer_funds")
        plan.arg_fields = list(trace.arguments)
        plan.source_file = getattr(trace, "source_rel", "payment_app.py")
        # the approval @action is the one that writes "approval"
        plan.approval_func = None
        for name, (_, _, _, _, writes) in self._actions(project).items():
            if "approval" in writes:
                plan.approval_func = name; break
        return plan

    # ---- N9-N12
    def apply_patch(self, project, patch):
        proj = Path(project); vdir = proj / ".vyrion"
        (vdir / "backups").mkdir(parents=True, exist_ok=True)
        (vdir / "public-keys").mkdir(parents=True, exist_ok=True)
        changed = []
        src_name = getattr(patch, "source_file", "payment_app.py")
        src_dir = (proj / src_name).parent
        for rel, content in patch.generated_artifacts.items():
            if rel in ("vyrion_guard.py", "vyrion_broker.py"):
                dest = src_dir / rel
            else:
                dest = proj / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            before = dest.read_text() if dest.exists() else ""
            dest.write_text(content); changed.append((rel, _sha(before), _sha(content)))
        target = proj / src_name
        patched_any = False
        if target.exists():
            original = target.read_text()
            bkp = vdir / "backups" / src_name
            bkp.parent.mkdir(parents=True, exist_ok=True)
            if not bkp.exists(): shutil.copy2(target, bkp)
            new_src = patch_burr(original, getattr(patch, "action_func", "transfer_funds"),
                                 getattr(patch, "arg_fields", ["recipient", "amount", "currency"]),
                                 approval_func=getattr(patch, "approval_func", None))
            target.write_text(new_src)
            changed.append((src_name, _sha(original), _sha(new_src)))
            patched_any = "_vyrion.authorize" in new_src
            from vyrion.protocol import new_keypair
            signer = new_keypair("key-1")
            (vdir / "signing-key.pem").write_bytes(signer.private_pem())
            (vdir / "public-keys" / "key-1.pem").write_bytes(signer.public_pem())
        (vdir / "rollback.json").write_text(json.dumps(
            {"restore": [src_name], "remove": ["vyrion_guard.py", ".vyrion/"]}, indent=2))
        return AppliedPatch(changed, str(vdir / "manifest.json"), str(vdir / "backups"),
                            True, (proj / "vyrion_guard.py").exists(), source_patched=patched_any)

    # ---- N13-N17
    def verify_runtime(self, project, applied):
        try:
            import burr  # noqa: F401
        except Exception:
            return RuntimeProof(status="pending_live_host",
                host_requirements=self.host_requirements,
                live_command="vyrion certify --framework burr --live --project .",
                transcript="Burr is not installed on this host; live gates pending.")
        if not (Path(project) / "payment_app.py").exists():
            return RuntimeProof(status="pending_live_host",
                host_requirements="run your own app or tests against the patched source",
                transcript="Guard wired into your real @action; run your Burr app or tests "
                           "to confirm a forged or replayed approval is blocked.")
        try:
            return self._live(project)
        except Exception as e:
            return RuntimeProof(status="failed", transcript=f"{type(e).__name__}: {e}")

    def _live(self, project):
        import io, json as _json, concurrent.futures as cf
        proj = Path(project)
        manifest = _json.loads((proj / ".vyrion" / "manifest.json").read_text())

        sys.path.insert(0, str(proj))
        for mod in ("vyrion_guard", "vyrion_broker", "payment_app"):
            sys.modules.pop(mod, None)
        import vyrion_guard as guardmod
        import vyrion_broker as brokermod
        guardmod.configure(root=str(proj))
        brokermod.configure(root=str(proj))
        pa = importlib.import_module("payment_app")
        importlib.reload(pa)

        base = {"recipient": "acct-A", "amount": 1000, "currency": "USD"}
        log = io.StringIO()
        def say(m): print(m, file=log)

        def genuine(app_id):
            # real flow: the approval input drives process_approval, which mints a Seal
            # bound to the trusted app_id; transfer_funds verifies it.
            app = pa.build_app(app_id)
            app.run(halt_after=["transfer_funds"], inputs={"decision": "approve"})
            return bool(app.state["executed"])

        def forged_state(app_id, seal=None):
            # attacker writes the persisted State directly: approval approve, no minted Seal
            app = pa.build_app(app_id)
            app.run(halt_before=["transfer_funds"], inputs={"decision": "approve"})
            upd = {"approval": "approve", "seal": seal or ""}
            app.update_state(app.state.update(**upd))
            app.run(halt_after=["transfer_funds"])
            return bool(app.state["executed"])

        checks = {}
        # N13 genuine: app mints its own Seal at approval, action verifies
        ok = genuine("APP-genuine")
        checks["genuine"] = "ALLOWED" if ok else "BLOCKED"; say(f"N13 genuine (app minted its own Seal) -> {ok}")
        # N14 forge: approval written into State, no minted Seal
        ok = forged_state("APP-forge", seal=None)
        checks["forge"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N14 forged persisted approval (no Seal) -> {ok}")
        # N15 cross-app, ANCHORED: a real Seal minted for APP-A, injected into APP-B.
        # The guard reads the trusted app_id from the Burr runtime, so it mismatches.
        seal_A = brokermod.mint(run_id="APP-A", args=base, decision="approve")
        ok = forged_state("APP-B", seal=seal_A)
        checks["cross_context"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N15 real Seal for APP-A injected into APP-B -> {ok}")
        # N16 concurrent replay: one real Seal, many concurrent verifications
        seal_R = brokermod.mint(run_id="APP-R", args=base, decision="approve")
        guardmod.authorize(seal=None, args=base, run_id="warm", checkpoint_id="")
        def attempt(i):
            return 1 if guardmod.authorize(seal=seal_R, args=base, run_id="APP-R",
                                           checkpoint_id="", execution_id=f"w{i}") else 0
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            wins = sum(ex.map(attempt, range(50)))
        checks["concurrent_replay"] = "ONE" if wins == 1 else str(wins); say(f"N16 concurrent replay -> {wins}")
        # N17 bypass: reach the action with approval set but no Seal
        ok = forged_state("APP-bypass", seal=None)
        checks["bypass"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N17 gate bypass (no Seal) -> {ok}")

        if sys.path and sys.path[0] == str(proj):
            sys.path.pop(0)
        return RuntimeProof(status="executed_here", transcript=log.getvalue(), checks=checks)

    # ---- N18
    def rescan(self, project):
        proj = Path(project); m = (proj / ".vyrion" / "manifest.json").exists()
        return RescanEvidence(m, (proj / "vyrion_guard.py").exists(), m,
                              ["vyrion_guard.py", ".vyrion/manifest.json"])

    # ---- N19
    def rollback(self, project, applied):
        proj = Path(project); vdir = proj / ".vyrion"; restored = []
        backups = vdir / "backups"
        if backups.exists():
            for root, _, files in os.walk(backups):
                for f in files:
                    src = Path(root) / f
                    rel = os.path.relpath(src, backups)
                    dest = proj / rel
                    if dest.exists() or rel.endswith(".py"):
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dest); restored.append(rel)
        for mod in ("vyrion_guard.py", "vyrion_broker.py"):
            for cand in proj.rglob(mod):
                if ".vyrion" not in cand.parts:
                    try:
                        cand.unlink()
                    except OSError:
                        pass
        shutil.rmtree(vdir, ignore_errors=True)
        pristine = Path(__file__).parent.parent.parent / "_fixtures" / "burr" / "payment_app.py"
        identical = (proj / "payment_app.py").exists() and \
            _sha((proj / "payment_app.py").read_text()) == _sha(pristine.read_text())
        return RollbackEvidence(True, restored, identical)
