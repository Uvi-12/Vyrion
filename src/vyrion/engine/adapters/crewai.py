"""Native adapter for CrewAI Flows (human-in-the-loop approval gates).

A CrewAI Flow pauses at a @human_feedback point; on resume the persisted feedback
is trusted and the guarded @listen method runs. A writer of the flow_states /
pending_feedback store can inject the approval (the Ghost Approval surface).

CrewAI exposes no trusted run identity to a flow method: flow_id == state.id, which
lives in the writable persisted state. So Vyrion does NOT run-anchor here; it binds
the Seal to action + arguments + a single-use nonce, minted by the trusted approver
who supplies the feedback, and verifies it at the protected @listen method.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..protection.templates import GUARD_MODULE, BROKER_MODULE
from ..protection.patcher import patch_crewai
from ..contract import (ActionTrace, AppliedPatch, ApprovalPointEvidence,
                        BindingAnalysis, DetectionEvidence, NativeAdapter,
                        PatchPlan, PersistenceEvidence, RescanEvidence, ResumeEvidence,
                        RollbackEvidence, RuntimeProof, SourceEvidence)


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()[:16]


_RUNNER = r'''
import sys, json, os, importlib
PROJ = sys.argv[1]
sys.path.insert(0, PROJ)
import vyrion_guard, vyrion_broker

vyrion_guard.configure(root=PROJ); vyrion_broker.configure(root=PROJ)
from crewai.flow.flow_config import flow_config
import payment_flow

BASE = {"recipient": "acct-A", "amount": 1000, "currency": "USD"}


class Stub:
    def __init__(self, m): self._m = m
    def request_feedback(self, context, flow): return self._m

def run(feedback, state_over=None):
    flow_config.hitl_provider = Stub(feedback)
    f = payment_flow.PaymentFlow()
    if state_over:
        for k, v in state_over.items():
            setattr(f.state, k, v)
    try:
        f.kickoff()
    except Exception:
        pass
    return bool(getattr(f.state, "settled", False))

def mkseal(args=BASE):
    return vyrion_broker.mint(run_id="", args=args, decision="approve")

r = {}
# N13 genuine
r["genuine"] = "ALLOWED" if run(mkseal()) else "BLOCKED"
# N14 forge: bare approval, no Seal
r["forge"] = "BLOCKED" if not run("approve") else "ALLOWED"
# N15 rebind: Seal for amount=1000, state tampered to 999999 before the action
r["cross_context"] = "BLOCKED" if not run(mkseal({"recipient":"acct-A","amount":1000,"currency":"USD"}),
                                          state_over={"amount": 999999}) else "ALLOWED"
# N16 replay: one Seal, many concurrent verifications, single-use nonce
import concurrent.futures as cf
seal2 = mkseal()
vyrion_guard.authorize(seal=None, args=BASE, run_id="", checkpoint_id="")
def attempt(i):
    return 1 if vyrion_guard.authorize(seal=seal2, args=BASE, run_id="", checkpoint_id="",
                                       execution_id="w%d" % i) else 0
with cf.ThreadPoolExecutor(max_workers=16) as ex:
    wins = sum(ex.map(attempt, range(50)))
r["concurrent_replay"] = "ONE" if wins == 1 else str(wins)
# N17 bypass: reach the action with no Seal
r["bypass"] = "BLOCKED" if not run("approve") else "ALLOWED"

print("VYRION_RESULTS " + json.dumps(r))
sys.stdout.flush()
os._exit(0)
'''


def _framework_missing(mod):
    """True if a framework package is not importable. Safe when a parent
    namespace is absent (find_spec raises rather than returning None)."""
    import importlib.util
    try:
        return importlib.util.find_spec(mod) is None
    except (ModuleNotFoundError, ValueError):
        return True


class CrewAINativeAdapter(NativeAdapter):
    framework = "CrewAI Flows"
    native_package = "vyrion-crewai"
    host_requirements = "pip install crewai"

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
                    if mod.startswith("crewai") or "crewai" in [a.name for a in n.names]:
                        hits.append(self._ev(path, n, text, "crewai import"))
        return DetectionEvidence(detected=bool(hits), framework=self.framework, evidence=hits)

    def detect_version(self, project):
        try:
            import importlib.metadata as m
            return m.version("crewai")
        except Exception:
            return "unknown"

    def _has_deco(self, node, name):
        for d in node.decorator_list:
            f = d.func if isinstance(d, ast.Call) else d
            if isinstance(f, ast.Name) and f.id == name:
                return d
            if isinstance(f, ast.Attribute) and f.attr == name:
                return d
        return None

    def _flow_shape(self, project):
        """Find the @human_feedback approval method and the protected @listen method
        that runs after it (and receives the feedback arg). Returns
        (path, action_func, feedback_param, approval_func, arg_fields, source_rel)."""
        for path in self._py_files(project):
            text = Path(path).read_text()
            if "human_feedback" not in text or "crewai" not in text:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for cls in ast.walk(tree):
                if not isinstance(cls, ast.ClassDef):
                    continue
                approval = None
                for m in cls.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and self._has_deco(m, "human_feedback"):
                        approval = m.name
                if not approval:
                    continue
                # the protected method @listen(approval) that takes a feedback param
                for m in cls.body:
                    if not isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    d = self._has_deco(m, "listen")
                    if not d or not isinstance(d, ast.Call) or not d.args:
                        continue
                    tgt = d.args[0]
                    tgt_name = tgt.id if isinstance(tgt, ast.Name) else None
                    if tgt_name != approval:
                        continue
                    params = [a.arg for a in m.args.args if a.arg != "self"]
                    if not params:
                        continue
                    fb_param = params[0]
                    # arg fields = self.state.X reads in this method, minus what it assigns
                    reads, writes = set(), set()
                    for n in ast.walk(m):
                        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Attribute) \
                                and isinstance(n.value.value, ast.Name) and n.value.value.id == "self" \
                                and n.value.attr == "state":
                            reads.add(n.attr)
                        if isinstance(n, ast.Assign):
                            for t in n.targets:
                                if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Attribute) \
                                        and getattr(t.value.value, "id", None) == "self" and t.value.attr == "state":
                                    writes.add(t.attr)
                    args = [a for a in reads if a not in writes and a != "settled"]
                    return (path, m.name, fb_param, approval, (sorted(args) or ["amount"]),
                            os.path.relpath(path, project))
        return None

    def discover_approval_points(self, project):
        s = self._flow_shape(project)
        if not s:
            return []
        path, _, _, approval, _, _ = s
        text = Path(path).read_text()
        for n in ast.walk(ast.parse(text)):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == approval:
                return [ApprovalPointEvidence("crewai-approval", "@human_feedback gate",
                                              self._ev(path, n, text, f"@human_feedback {approval}()"))]
        return []

    def discover_persistence(self, project):
        return [PersistenceEvidence("CrewAI flow_states / pending_feedback (SQLite)",
                                    "state.last_human_feedback", True)]

    def discover_resume(self, project):
        return [ResumeEvidence("Flow.from_pending(flow_id).resume(feedback)")]

    def trace_actions(self, project, approval):
        s = self._flow_shape(project)
        if not s:
            return []
        path, action_func, fb_param, approval_func, args, rel = s
        text = Path(path).read_text()
        for n in ast.walk(ast.parse(text)):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == action_func:
                tr = ActionTrace(approval.id, f"action.{action_func}", "CrewAI @listen method",
                                 args, ["approval"] + args, self._ev(path, n, text, f"@listen {action_func}()"))
                tr.action_func = action_func
                tr.feedback_param = fb_param
                tr.approval_func = approval_func
                tr.source_rel = rel
                return [tr]
        return []

    def analyze_bindings(self, trace):
        return BindingAnalysis(missing=["approver_authenticated", "action_bound",
            "arguments_bound", "replay_protected", "verified_at_execution"])

    def generate_patch(self, project, trace):
        fp = _sha(trace.evidence.snippet)
        rel = getattr(trace, "source_rel", "payment_flow.py")
        manifest = {"schema": "vyrion.manifest.v1", "framework": "crewai",
                    "approval_point": trace.approval_id, "action_id": trace.action_id,
                    "action_fingerprint": fp, "environment": "production",
                    "audience": "payments", "tenant": "default", "fail_mode": "closed",
                    "public_keys": "public-keys/", "source_file": rel}
        plan = PatchPlan(
            steps=["back up the flow source",
                   "patch source: verify the feedback as a provenance-bound Seal at the guarded @listen",
                   "install vyrion_guard.py + vyrion_broker.py", "create .vyrion/manifest.json"],
            files_touched=[rel],
            generated_artifacts={"vyrion_guard.py": GUARD_MODULE,
                                 "vyrion_broker.py": BROKER_MODULE,
                                 ".vyrion/manifest.json": json.dumps(manifest, indent=2)},
            native_package=self.native_package)
        plan.action_fingerprint = fp
        plan.action_func = getattr(trace, "action_func", "transfer_funds")
        plan.feedback_param = getattr(trace, "feedback_param", "feedback")
        plan.arg_fields = list(trace.arguments)
        plan.source_file = rel
        return plan

    def apply_patch(self, project, patch):
        proj = Path(project); vdir = proj / ".vyrion"
        (vdir / "backups").mkdir(parents=True, exist_ok=True)
        (vdir / "public-keys").mkdir(parents=True, exist_ok=True)
        changed = []
        src_rel = getattr(patch, "source_file", "payment_flow.py")
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
            new_src = patch_crewai(original, getattr(patch, "action_func", "transfer_funds"),
                                   getattr(patch, "feedback_param", "feedback"),
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
        if _framework_missing("crewai"):
            return RuntimeProof(status="pending_live_host",
                host_requirements=self.host_requirements,
                live_command="vyrion certify --framework crewai --live --project .",
                transcript="CrewAI is not installed on this host; live gates pending.")
        if not (Path(project) / "payment_flow.py").exists():
            return RuntimeProof(status="pending_live_host",
                host_requirements="run your own CrewAI flow or tests against the patched source",
                transcript="Guard wired into your @listen action: it verifies the human feedback "
                           "as a provenance-bound Seal (action + args + single-use nonce; CrewAI "
                           "exposes no trusted run id to a flow method). Run your flow to confirm a "
                           "forged or replayed approval is blocked.")
        try:
            return self._live(project)
        except Exception as e:
            return RuntimeProof(status="failed", transcript=f"{type(e).__name__}: {e}")

    def _live(self, project):
        proj = Path(project)
        # CrewAI leaves non-daemon telemetry threads alive after a flow finishes, which
        # would hang this process at exit; run the real flow cases in a subprocess.
        runner = proj / "_vyrion_crew_runner.py"
        runner.write_text(_RUNNER)
        try:
            out = subprocess.run([sys.executable, str(runner), str(proj)],
                                 capture_output=True, text=True, timeout=180)
        finally:
            try:
                runner.unlink()
            except OSError:
                pass
        line = next((l for l in out.stdout.splitlines() if l.startswith("VYRION_RESULTS ")), None)
        if not line:
            return RuntimeProof(status="failed",
                                transcript=(out.stdout + "\n" + out.stderr)[-2000:])
        checks = json.loads(line[len("VYRION_RESULTS "):])
        transcript = "\n".join(f"{k} -> {v}" for k, v in checks.items())
        return RuntimeProof(status="executed_here", transcript=transcript, checks=checks)

    def rescan(self, project):
        proj = Path(project); m = (proj / ".vyrion" / "manifest.json").exists()
        s = self._flow_shape(project)
        src_dir = (proj / s[5]).parent if s else proj
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
        for mod in ("vyrion_guard.py", "vyrion_broker.py", "_vyrion_crew_runner.py"):
            for cand in proj.rglob(mod):
                if ".vyrion" not in cand.parts:
                    try:
                        cand.unlink()
                    except OSError:
                        pass
        shutil.rmtree(vdir, ignore_errors=True)
        pristine = Path(__file__).parent.parent.parent / "_fixtures" / "crewai" / "payment_flow.py"
        sample = proj / "payment_flow.py"
        identical = sample.exists() and (_sha(sample.read_text()) == _sha(pristine.read_text()))
        return RollbackEvidence(True, restored, identical)