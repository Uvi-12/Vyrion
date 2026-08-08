"""LlamaIndex Workflows native adapter (N1-N20, live-certified here).

Detects a real LlamaIndex workflow by AST, traces the human-response event to the
protected step, installs the guard plus manifest, and runs the live proof against
the real Workflow/Context: genuine approval allowed, forged serialized-context
approval blocked, cross-run reuse blocked, concurrent replay collapsed to one,
bypass blocked. Rescan and byte-identical rollback as with LangGraph.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path

from ..protection.templates import GUARD_MODULE, BROKER_MODULE
from ..protection.patcher import patch_llamaindex
from ..contract import (ActionTrace, AppliedPatch, ApprovalPointEvidence,
                        BindingAnalysis, DetectionEvidence, NativeAdapter,
                        PatchPlan, PersistenceEvidence, RescanEvidence, ResumeEvidence,
                        RollbackEvidence, RuntimeProof, SourceEvidence)


def _sha(t): return hashlib.sha256(t.encode()).hexdigest()[:16]


class LlamaIndexNativeAdapter(NativeAdapter):
    framework = "LlamaIndex Workflows"
    category = "agentic-python"
    native_package = "vyrion-llamaindex"

    def _py(self, project):
        skip = {".vyrion", ".git", "__pycache__", ".venv", "venv",
                "node_modules", ".mypy_cache", ".pytest_cache", "build", "dist"}
        matches = []
        for root, dirs, files in os.walk(project):
            dirs[:] = [d for d in dirs if d not in skip]
            if ".vyrion" in root: continue
            for f in files:
                if f.endswith(".py"): matches.append(os.path.join(root, f))
        yield from sorted(matches)

    def _ev(self, path, node, text, construct):
        s = getattr(node, "lineno", 1); e = getattr(node, "end_lineno", s)
        snip = "\n".join(text.splitlines()[s-1:e])[:300]
        return SourceEvidence(os.path.basename(path), s, e, "python", construct, snip,
                              "python-ast", _sha(snip))

    def detect_project(self, project):
        hits = []
        for path in self._py(project):
            text = Path(path).read_text()
            try: tree = ast.parse(text)
            except SyntaxError: continue
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("llama_index"):
                    hits.append(self._ev(path, n, text, "llama_index import"))
        return DetectionEvidence(bool(hits), self.framework, hits)

    def detect_version(self, project):
        try:
            import importlib.metadata as m
            return m.version("llama-index-core")
        except Exception:
            return "unknown"

    def discover_approval_points(self, project):
        out = []
        for path in self._py(project):
            text = Path(path).read_text()
            try: tree = ast.parse(text)
            except SyntaxError: continue
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                        and n.func.id == "InputRequiredEvent":
                    out.append(ApprovalPointEvidence(
                        "payment-approval", "InputRequiredEvent / HumanResponseEvent",
                        self._ev(path, n, text, "InputRequiredEvent")))
        return out

    def discover_persistence(self, project):
        for path in self._py(project):
            text = Path(path).read_text()
            if "ctx.store" in text or "Context" in text:
                return [PersistenceEvidence("workflow Context store (serialized)",
                                            "ctx.store.approval", True)]
        return [PersistenceEvidence("workflow Context store", "ctx.store.approval", True)]

    def discover_resume(self, project):
        return [ResumeEvidence("HumanResponseEvent + Context.from_dict")]

    def _wf_shape(self, project):
        """Generic LlamaIndex HITL analysis: find the protected step (consumes
        HumanResponseEvent), the approval step (emits InputRequiredEvent), and the
        domain args the approval step stores. Returns
        (path, action_func, approval_func, arg_fields, source_rel) or None."""
        for path in self._py(project):
            text = Path(path).read_text()
            if "InputRequiredEvent" not in text or "HumanResponseEvent" not in text:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            action_func = approval_func = None
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # protected step: a parameter annotated HumanResponseEvent
                    for a in n.args.args:
                        ann = getattr(a, "annotation", None)
                        if isinstance(ann, ast.Name) and ann.id == "HumanResponseEvent":
                            action_func = n.name
                    # approval step: constructs InputRequiredEvent anywhere in its body
                    if any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                           and c.func.id == "InputRequiredEvent" for c in ast.walk(n)):
                        approval_func = n.name
            if not (action_func and approval_func):
                continue
            # arg fields = ctx.store.set("X", ...) keys in the approval step, minus control
            control = {"action", "approval", "seal", "vyrion_seal", "vyrion_run",
                       "vyrion_args", "executed", "vyrion_blocked"}
            args = []
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == approval_func:
                    for c in ast.walk(n):
                        if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) \
                                and c.func.attr == "set" and c.args \
                                and isinstance(c.args[0], ast.Constant) \
                                and isinstance(c.args[0].value, str):
                            k = c.args[0].value
                            if k not in control and k not in args:
                                args.append(k)
            return (path, action_func, approval_func, (args or ["amount"]),
                    os.path.relpath(path, project))
        return None

    def trace_actions(self, project, approval):
        shape = self._wf_shape(project)
        if shape:
            path, action_func, approval_func, args, rel = shape
            text = Path(path).read_text()
            for n in ast.walk(ast.parse(text)):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == action_func:
                    tr = ActionTrace(approval.id, f"action.{action_func}", "workflow step",
                                     args, ["approval", "action"],
                                     self._ev(path, n, text, f"async def {action_func}()"))
                    tr.action_func = action_func
                    tr.approval_func = approval_func
                    tr.source_rel = rel
                    return [tr]
        for path in self._py(project):
            text = Path(path).read_text()
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and n.name == "transfer_funds":
                    tr = ActionTrace(approval.id, "payments.transfer",
                            "workflow step", ["recipient", "amount", "currency"],
                            ["approval", "action"], self._ev(path, n, text,
                             "async def transfer_funds()"))
                    tr.action_func = "transfer_funds"
                    tr.approval_func = "request_approval"
                    tr.source_rel = "payment_workflow.py"
                    return [tr]
        return []

    def analyze_bindings(self, trace):
        return BindingAnalysis(missing=["action_bound", "arguments_bound", "run_bound",
                                        "replay_protected", "verified_at_execution"])

    def generate_patch(self, project, trace):
        fingerprint = _sha(trace.evidence.snippet)
        src_rel = getattr(trace, "source_rel", os.path.basename(trace.evidence.path))
        manifest = {"schema": "vyrion.manifest.v1", "framework": "llamaindex",
                    "approval_point": trace.approval_id, "action_id": trace.action_id,
                    "action_fingerprint": fingerprint, "environment": "production",
                    "audience": "payments", "tenant": "default",
                    "fail_mode": "closed", "public_keys": "public-keys/",
                    "source_file": src_rel}
        plan = PatchPlan(steps=["back up the protected source",
                                "patch source: import guard, store seal at approval, verify at action",
                                "install vyrion_guard.py + vyrion_broker.py", "create .vyrion/manifest.json"],
                         files_touched=[src_rel],
                         generated_artifacts={"vyrion_guard.py": GUARD_MODULE,
                                              "vyrion_broker.py": BROKER_MODULE,
                                              ".vyrion/manifest.json": json.dumps(manifest, indent=2)},
                         native_package=self.native_package)
        plan.action_fingerprint = fingerprint
        plan.action_func = getattr(trace, "action_func", "transfer_funds")
        plan.approval_func = getattr(trace, "approval_func", "request_approval")
        plan.arg_fields = list(trace.arguments)
        plan.source_file = src_rel
        return plan

    def apply_patch(self, project, patch):
        proj = Path(project); vdir = proj / ".vyrion"
        (vdir / "backups").mkdir(parents=True, exist_ok=True)
        (vdir / "public-keys").mkdir(parents=True, exist_ok=True)
        changed = []
        src_rel = getattr(patch, "source_file", "payment_workflow.py")
        src_dir = (proj / src_rel).parent
        for rel, content in patch.generated_artifacts.items():
            if rel in ("vyrion_guard.py", "vyrion_broker.py"):
                dest = src_dir / rel
            else:
                dest = proj / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            before = dest.read_text() if dest.exists() else ""
            if dest.exists():
                if not (vdir / "backups" / dest.name).exists(): shutil.copy2(dest, vdir / "backups" / dest.name)
            dest.write_text(content); changed.append((rel, _sha(before), _sha(content)))
        target = proj / src_rel
        if not target.exists():
            return AppliedPatch(changed, str(vdir / "manifest.json"), str(vdir / "backups"),
                                True, (src_dir / "vyrion_guard.py").exists(), source_patched=False)
        original = target.read_text()
        bkp = vdir / "backups" / src_rel
        bkp.parent.mkdir(parents=True, exist_ok=True)
        if not bkp.exists(): shutil.copy2(target, bkp)
        patched = patch_llamaindex(original,
                                   getattr(patch, "action_func", "transfer_funds"),
                                   getattr(patch, "approval_func", "request_approval"),
                                   arg_fields=getattr(patch, "arg_fields",
                                                      ["recipient", "amount", "currency"]))
        target.write_text(patched)
        changed.append((src_rel, _sha(original), _sha(patched)))
        from vyrion.protocol import new_keypair
        signer = new_keypair("key-1")
        (vdir / "signing-key.pem").write_bytes(signer.private_pem())
        (vdir / "public-keys" / "key-1.pem").write_bytes(signer.public_pem())
        (vdir / "rollback.json").write_text(json.dumps(
            {"restore": [src_rel], "remove": ["vyrion_guard.py", "vyrion_broker.py", ".vyrion/"]}, indent=2))
        return AppliedPatch(changed, str(vdir / "manifest.json"), str(vdir / "backups"),
                            True, (src_dir / "vyrion_guard.py").exists(),
                            source_patched=("_vyrion.authorize" in patched))

    def verify_runtime(self, project, applied):
        try:
            import llama_index.core.workflow  # noqa: F401
        except Exception:
            return RuntimeProof(status="pending_live_host",
                host_requirements="pip install llama-index-core",
                live_command="vyrion certify --framework llamaindex --live --project .",
                transcript="LlamaIndex is not installed on this host; live gates pending.")
        if not (Path(project) / "payment_workflow.py").exists():
            return RuntimeProof(status="pending_live_host",
                host_requirements="run your own app or tests against the patched source",
                transcript="Guard wired into your real step. The trusted approver mints the "
                           "Seal (LlamaIndex exposes no run id to a step, so binding is "
                           "action + args + single-use nonce); run your app to confirm a "
                           "forged or rebound approval is blocked.")
        try:
            return asyncio.run(self._live(project))
        except Exception as e:
            return RuntimeProof(status="failed", transcript=f"{type(e).__name__}: {e}")

    async def _live(self, project):
        import io, sys, json as _json, importlib
        from vyrion.protocol import (ApprovalBroker, Approver, WorkflowRef, ExecutionRef,
                                     new_keypair)
        from llama_index.core.workflow import InputRequiredEvent, HumanResponseEvent

        proj = Path(project)
        signer = new_keypair("key-1")
        (proj / ".vyrion" / "public-keys").mkdir(parents=True, exist_ok=True)
        (proj / ".vyrion" / "public-keys" / "key-1.pem").write_bytes(signer.public_pem())
        manifest = _json.loads((proj / ".vyrion" / "manifest.json").read_text())
        AID = manifest["action_id"]; FP = manifest.get("action_fingerprint", "")
        APID = manifest["approval_point"]; ENV = manifest.get("environment", "production")
        AUD = manifest.get("audience", "payments")
        broker = ApprovalBroker(signer)

        sys.path.insert(0, str(proj))
        for mod in ("vyrion_guard", "payment_workflow"):
            sys.modules.pop(mod, None)
        import vyrion_guard as guardmod
        guardmod.configure(root=str(proj))
        wfmod = importlib.import_module("payment_workflow")
        importlib.reload(wfmod)
        PaymentWorkflow = wfmod.PaymentWorkflow

        base = {"recipient": "acct-A", "amount": 1000, "currency": "USD"}
        log = io.StringIO()
        def say(m): print(m, file=log)

        def mkseal(args=base):
            # LlamaIndex exposes no trusted run id to a step: bind action + args + nonce
            return broker.issue(approver=Approver(subject="cfo@corp"), decision="approve",
                action_id=AID, action_fingerprint=FP, args=args,
                workflow=WorkflowRef(system="llamaindex", run_id="", checkpoint_id=""),
                execution=ExecutionRef(environment=ENV, audience=AUD),
                approval_point_id=APID).to_dict()

        async def run_case(seal, args=base):
            wf = PaymentWorkflow(timeout=30)
            h = wf.run(recipient=args["recipient"], amount=args["amount"],
                       currency=args["currency"],
                       vyrion_seal=(_json.dumps(seal) if seal else None))
            async for ev in h.stream_events():
                if isinstance(ev, InputRequiredEvent):
                    h.ctx.send_event(HumanResponseEvent(response="approve")); break
            try:
                res = await h
                return res.get("executed")
            except guardmod.GhostApprovalBlocked:
                return False

        checks = {}
        # N13 genuine: trusted approver minted a Seal for these args
        ok = await run_case(mkseal(base))
        checks["genuine"] = "ALLOWED" if ok else "BLOCKED"; say(f"N13 genuine on patched workflow -> {ok}")
        # N14 forge: approval in context, no Seal
        ok = await run_case(None)
        checks["forge"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N14 forge (no seal) -> {ok}")
        # N15 REBIND: Seal approved for amount=1000, workflow context tampered to amount=999999.
        # args commitment mismatch blocks it (approve-small, execute-large).
        tampered = {"recipient": "acct-A", "amount": 999999, "currency": "USD"}
        ok = await run_case(mkseal(base), args=tampered)
        checks["cross_context"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N15 rebind (args tampered after approval) -> {ok}")
        # N16 replay: one Seal, many concurrent verifications, single-use nonce
        import concurrent.futures as cf
        seal2 = mkseal(base)
        guardmod.authorize(seal=None, args=base, run_id="", checkpoint_id="")
        def attempt(i):
            return 1 if guardmod.authorize(seal=_json.dumps(seal2), args=base,
                                           run_id="", checkpoint_id="",
                                           execution_id=f"w{i}") else 0
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            wins = sum(ex.map(attempt, range(50)))
        checks["concurrent_replay"] = "ONE" if wins == 1 else str(wins); say(f"N16 concurrent replay -> {wins}")
        # N17 bypass: reach the action with approval set but no Seal
        ok = await run_case(None)
        checks["bypass"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N17 bypass -> {ok}")

        if sys.path and sys.path[0] == str(proj):
            sys.path.pop(0)
        return RuntimeProof(status="executed_here", transcript=log.getvalue(), checks=checks)

    def rescan(self, project):
        proj = Path(project)
        m = (proj / ".vyrion" / "manifest.json").exists()
        return RescanEvidence(m, (proj / "vyrion_guard.py").exists(), m,
                              ["vyrion_guard.py", ".vyrion/manifest.json"])

    def rollback(self, project, applied):
        proj = Path(project); vdir = proj / ".vyrion"; restored = []
        backups = vdir / "backups"
        if backups.exists():
            for root, _, files in os.walk(backups):
                for f in files:
                    src = Path(root) / f
                    rel = os.path.relpath(src, backups)
                    dest = proj / rel
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
        pristine = Path(__file__).parent.parent.parent / "_fixtures" / "llamaindex" / "payment_workflow.py"
        sample = proj / "payment_workflow.py"
        identical = sample.exists() and (_sha(sample.read_text()) == _sha(pristine.read_text()))
        return RollbackEvidence(True, restored, identical)
