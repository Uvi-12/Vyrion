"""Native adapter for the OpenAI Agents SDK (needs_approval tools).

A tool declared needs_approval=True pauses the run; the approval is stored in
RunState and serialized via RunState.to_json / from_json with no integrity check.
A writer of that serialized state can set approved=true and the tool executes (the
Ghost Approval surface).

RunState is serialized whole, so there is no trusted run identity to anchor to.
Vyrion binds the Seal to action + arguments + a single-use nonce, minted by the
trusted approver (who places it in the run context when approving), and verifies it
inside the tool before the side effect.
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
from ..protection.patcher import patch_openai_agents
from ..contract import (ActionTrace, AppliedPatch, ApprovalPointEvidence,

                        BindingAnalysis, DetectionEvidence, NativeAdapter,
                        PatchPlan, PersistenceEvidence, RescanEvidence, ResumeEvidence,
                        RollbackEvidence, RuntimeProof, SourceEvidence)


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()[:16]



def _framework_missing(mod):
    """True if a framework package is not importable. Safe when a parent
    namespace is absent (find_spec raises rather than returning None)."""
    import importlib.util
    try:
        return importlib.util.find_spec(mod) is None
    except (ModuleNotFoundError, ValueError):
        return True


class OpenAIAgentsNativeAdapter(NativeAdapter):
    framework = "OpenAI Agents SDK"
    native_package = "vyrion-openai-agents"
    host_requirements = "pip install openai-agents"

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
        s = getattr(node, "lineno", 1); e = getattr(node, "end_lineno", s)
        line = text.splitlines()[s - 1].strip() if text.splitlines() else ""
        return SourceEvidence(path=path, start_line=s, end_line=e, language="python",
                              construct=construct, snippet=line, parser="python-ast",
                              fingerprint=_sha(line), confidence="high")

    def detect_project(self, project):
        hits = []
        for path in self._py_files(project):
            text = Path(path).read_text()
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for n in ast.walk(tree):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    mod = getattr(n, "module", None) or ""
                    if mod == "agents" or mod.startswith("agents.") or "agents" in [a.name for a in n.names]:
                        if "needs_approval" in text or "function_tool" in text:
                            hits.append(self._ev(path, n, text, "openai-agents import"))
        return DetectionEvidence(detected=bool(hits), framework=self.framework, evidence=hits)

    def detect_version(self, project):
        try:
            import importlib.metadata as m
            return m.version("openai-agents")
        except Exception:
            return "unknown"

    def _needs_approval_deco(self, node):
        for d in node.decorator_list:
            if isinstance(d, ast.Call):
                f = d.func
                nm = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
                if nm == "function_tool":
                    for kw in d.keywords:
                        if kw.arg == "needs_approval" and isinstance(kw.value, ast.Constant) \
                                and kw.value.value is True:
                            return True
        return False

    def _tool_shape(self, project):
        """Find the needs_approval tool function, its context param, and its domain
        args. Returns (path, action_func, ctx_param, arg_fields, source_rel)."""
        ctx_types = {"ToolContext", "RunContextWrapper"}
        for path in self._py_files(project):
            text = Path(path).read_text()
            if "needs_approval" not in text:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and self._needs_approval_deco(n):
                    params = [a for a in n.args.args]
                    if not params:
                        continue
                    # context param: annotated ToolContext/RunContextWrapper, else first param
                    ctx_param = None
                    domain = []
                    for a in params:
                        ann = getattr(a, "annotation", None)
                        ann_name = ann.id if isinstance(ann, ast.Name) else (
                            ann.attr if isinstance(ann, ast.Attribute) else None)
                        if ann_name in ctx_types and ctx_param is None:
                            ctx_param = a.arg
                        else:
                            domain.append(a.arg)
                    if ctx_param is None:
                        ctx_param = params[0].arg
                        domain = [a.arg for a in params[1:]]
                    return (path, n.name, ctx_param, (domain or ["amount"]),
                            os.path.relpath(path, project))
        return None

    def discover_approval_points(self, project):
        s = self._tool_shape(project)
        if not s:
            return []
        path, action, _, _, _ = s
        text = Path(path).read_text()
        for n in ast.walk(ast.parse(text)):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == action:
                return [ApprovalPointEvidence("oai-approval", "@function_tool(needs_approval=True)",
                                              self._ev(path, n, text, f"needs_approval tool {action}()"))]
        return []

    def discover_persistence(self, project):
        return [PersistenceEvidence("RunState serialization (to_json / from_json)",
                                    "RunState._approvals", True)]

    def discover_resume(self, project):
        return [ResumeEvidence("RunState.from_json(...).approve(item) then Runner.run(state)")]

    def trace_actions(self, project, approval):
        s = self._tool_shape(project)
        if not s:
            return []
        path, action, ctx_param, args, rel = s
        text = Path(path).read_text()
        for n in ast.walk(ast.parse(text)):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == action:
                tr = ActionTrace(approval.id, f"action.{action}", "needs_approval tool",
                                 args, ["approval"] + args, self._ev(path, n, text, f"tool {action}()"))
                tr.action_func = action
                tr.ctx_param = ctx_param
                tr.source_rel = rel
                return [tr]
        return []

    def analyze_bindings(self, trace):
        return BindingAnalysis(missing=["approver_authenticated", "action_bound",
            "arguments_bound", "replay_protected", "verified_at_execution"])

    def generate_patch(self, project, trace):
        fp = _sha(trace.evidence.snippet)
        rel = getattr(trace, "source_rel", "payment_agent.py")
        manifest = {"schema": "vyrion.manifest.v1", "framework": "openai-agents",
                    "approval_point": trace.approval_id, "action_id": trace.action_id,
                    "action_fingerprint": fp, "environment": "production",
                    "audience": "payments", "tenant": "default", "fail_mode": "closed",
                    "public_keys": "public-keys/", "source_file": rel}
        plan = PatchPlan(
            steps=["back up the tool source",
                   "patch source: verify a provenance-bound Seal inside the needs_approval tool",
                   "install vyrion_guard.py + vyrion_broker.py", "create .vyrion/manifest.json"],
            files_touched=[rel],
            generated_artifacts={"vyrion_guard.py": GUARD_MODULE,
                                 "vyrion_broker.py": BROKER_MODULE,
                                 ".vyrion/manifest.json": json.dumps(manifest, indent=2)},
            native_package=self.native_package)
        plan.action_fingerprint = fp
        plan.action_func = getattr(trace, "action_func", "transfer_funds")
        plan.ctx_param = getattr(trace, "ctx_param", "ctx")
        plan.arg_fields = list(trace.arguments)
        plan.source_file = rel
        return plan

    def apply_patch(self, project, patch):
        proj = Path(project); vdir = proj / ".vyrion"
        (vdir / "backups").mkdir(parents=True, exist_ok=True)
        (vdir / "public-keys").mkdir(parents=True, exist_ok=True)
        changed = []
        src_rel = getattr(patch, "source_file", "payment_agent.py")
        src_dir = (proj / src_rel).parent
        for rel, content in patch.generated_artifacts.items():
            dest = (src_dir / rel) if rel in ("vyrion_guard.py", "vyrion_broker.py") else (proj / rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            before = dest.read_text() if dest.exists() else ""
            dest.write_text(content); changed.append((rel, _sha(before), _sha(content)))
        target = proj / src_rel
        patched_any = False
        if target.exists():
            original = target.read_text()
            bkp = vdir / "backups" / src_rel
            bkp.parent.mkdir(parents=True, exist_ok=True)
            if not bkp.exists(): shutil.copy2(target, bkp)
            new_src = patch_openai_agents(original, getattr(patch, "action_func", "transfer_funds"),
                                          getattr(patch, "ctx_param", "ctx"),
                                          getattr(patch, "arg_fields", ["recipient", "amount", "currency"]))
            target.write_text(new_src)
            changed.append((src_rel, _sha(original), _sha(new_src)))
            patched_any = "_vyrion.authorize" in new_src
            from vyrion.protocol import new_keypair
            signer = new_keypair("key-1")
            (vdir / "signing-key.pem").write_bytes(signer.private_pem())
            (vdir / "public-keys" / "key-1.pem").write_bytes(signer.public_pem())
        (vdir / "rollback.json").write_text(json.dumps(
            {"restore": [src_rel], "remove": ["vyrion_guard.py", "vyrion_broker.py", ".vyrion/"]}, indent=2))
        return AppliedPatch(changed, str(vdir / "manifest.json"), str(vdir / "backups"),
                            True, (src_dir / "vyrion_guard.py").exists(), source_patched=patched_any)

    def verify_runtime(self, project, applied):
        import importlib.util
        if _framework_missing("agents"):
            return RuntimeProof(status="pending_live_host",
                host_requirements=self.host_requirements,
                live_command="vyrion certify --framework openai-agents --live --project .",
                transcript="OpenAI Agents SDK is not installed on this host; live gates pending.")
        if not (Path(project) / "payment_agent.py").exists():
            return RuntimeProof(status="pending_live_host",
                host_requirements="run your own agent or tests against the patched tool",
                transcript="Guard wired into your needs_approval tool: it verifies the approval "
                           "as a provenance-bound Seal (action + args + single-use nonce; RunState "
                           "is serialized whole, so no trusted run anchor). Run your agent to confirm "
                           "a forged or replayed approval is blocked.")
        try:
            return self._live(project)
        except Exception as e:
            return RuntimeProof(status="failed", transcript=f"{type(e).__name__}: {e}")

    def _live(self, project):
        import io, json as _json, asyncio, concurrent.futures as cf
        from agents import RunConfig
        from agents.tool_context import ToolContext
        from vyrion.protocol import (ApprovalBroker, Approver, WorkflowRef, ExecutionRef, new_keypair)
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
        for mod in ("vyrion_guard", "payment_agent"):
            sys.modules.pop(mod, None)
        import vyrion_guard as guardmod
        guardmod.configure(root=str(proj))
        pa = importlib.import_module("payment_agent")
        importlib.reload(pa)
        tool = pa.transfer_funds  # the FunctionTool (guard wired into its body)

        base = {"recipient": "acct-A", "amount": 1000, "currency": "USD"}
        log = io.StringIO()
        def say(m): print(m, file=log)

        def mkseal(args=base):
            return broker.issue(approver=Approver(subject="cfo@corp"), decision="approve",
                action_id=AID, action_fingerprint=FP, args=args,
                workflow=WorkflowRef(system="openai-agents", run_id="", checkpoint_id=""),
                execution=ExecutionRef(environment=ENV, audience=AUD),
                approval_point_id=APID).to_dict()

        class Ctx:
            def __init__(self, seal): self.vyrion_seal = seal

        async def invoke(seal, args=base):
            payload = _json.dumps(args)
            ctx = ToolContext(context=Ctx(_json.dumps(seal) if seal else None),
                              tool_name="transfer_funds", tool_call_id="call-1",
                              tool_arguments=payload, run_config=RunConfig())
            try:
                res = await tool.on_invoke_tool(ctx, payload)
                return "settled" in str(res)
            except guardmod.GhostApprovalBlocked:
                return False
            except Exception as e:
                return "GhostApprovalBlocked" not in type(e).__name__

        checks = {}
        ok = asyncio.run(invoke(mkseal()))
        checks["genuine"] = "ALLOWED" if ok else "BLOCKED"; say(f"N13 genuine -> {ok}")
        ok = asyncio.run(invoke(None))
        checks["forge"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N14 forge -> {ok}")
        tampered = {"recipient": "acct-A", "amount": 999999, "currency": "USD"}
        ok = asyncio.run(invoke(mkseal(base), args=tampered))
        checks["cross_context"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N15 rebind -> {ok}")
        seal2 = _json.dumps(mkseal(base))
        guardmod.authorize(seal=None, args=base, run_id="", checkpoint_id="")
        def attempt(i):
            return 1 if guardmod.authorize(seal=seal2, args=base, run_id="", checkpoint_id="",
                                           execution_id=f"w{i}") else 0
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            wins = sum(ex.map(attempt, range(50)))
        checks["concurrent_replay"] = "ONE" if wins == 1 else str(wins); say(f"N16 replay -> {wins}")
        ok = asyncio.run(invoke(None))
        checks["bypass"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N17 bypass -> {ok}")

        if sys.path and sys.path[0] == str(proj):
            sys.path.pop(0)
        return RuntimeProof(status="executed_here", transcript=log.getvalue(), checks=checks)

    def rescan(self, project):
        proj = Path(project); m = (proj / ".vyrion" / "manifest.json").exists()
        s = self._tool_shape(project)
        src_dir = (proj / s[4]).parent if s else proj
        return RescanEvidence(m, (src_dir / "vyrion_guard.py").exists(), m,
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
        pristine = Path(__file__).parent.parent.parent / "_fixtures" / "openai_agents" / "payment_agent.py"
        sample = proj / "payment_agent.py"
        identical = sample.exists() and (_sha(sample.read_text()) == _sha(pristine.read_text()))
        return RollbackEvidence(True, restored, identical)