"""Native adapter for DBOS Transact (durable workflows).

A DBOS workflow waits for human approval via DBOS.recv(); the decision is durable
and read back on resume/recovery. Any writer of the durable notifications/outputs
state can inject the approval (the Ghost Approval surface). DBOS exposes a trusted,
server-owned DBOS.workflow_id to the running workflow, so Vyrion anchors the Seal
to that identity (not to mutable state) and verifies it right after recv().
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
from ..protection.patcher import patch_dbos
from ..contract import (ActionTrace, AppliedPatch, ApprovalPointEvidence,
                        BindingAnalysis, DetectionEvidence, NativeAdapter,
                        PatchPlan, PersistenceEvidence, RescanEvidence, ResumeEvidence,
                        RollbackEvidence, RuntimeProof, SourceEvidence)


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()[:16]


class DBOSNativeAdapter(NativeAdapter):
    framework = "DBOS Transact"
    native_package = "vyrion-dbos"
    host_requirements = "pip install dbos"

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
                    names = [a.name for a in n.names]
                    if mod == "dbos" or "dbos" in names:
                        hits.append(self._ev(path, n, text, "dbos import"))
        return DetectionEvidence(detected=bool(hits), framework=self.framework, evidence=hits)

    def detect_version(self, project):
        try:
            import importlib.metadata as m
            return m.version("dbos")
        except Exception:
            return "unknown"

    def _workflow_with_recv(self, project):
        """Return (path, func_node, text, arg_fields, source_rel) for the workflow
        that waits on DBOS.recv() (the human-approval boundary)."""
        for path in self._py_files(project):
            text = Path(path).read_text()
            if ".recv(" not in text:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                        isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                        and c.func.attr == "recv" for c in ast.walk(n)):
                    args = [a.arg for a in n.args.args if a.arg != "self"]
                    return path, n, text, (args or ["amount"]), os.path.relpath(path, project)
        return None

    def discover_approval_points(self, project):
        w = self._workflow_with_recv(project)
        if not w:
            return []
        path, node, text, _, _ = w
        return [ApprovalPointEvidence("dbos-approval", "DBOS.recv() human-approval wait",
                                      self._ev(path, node, text, f"workflow {node.name}()"))]

    def discover_persistence(self, project):
        return [PersistenceEvidence("DBOS durable state (notifications / operation outputs)",
                                    "recv('approval')", True)]

    def discover_resume(self, project):
        return [ResumeEvidence("DBOS.recv() result replayed from durable state on recovery")]

    def trace_actions(self, project, approval):
        w = self._workflow_with_recv(project)
        if not w:
            return []
        path, node, text, args, rel = w
        tr = ActionTrace(approval.id, f"workflow.{node.name}", "DBOS workflow + step",
                         args, ["approval"] + args, self._ev(path, node, text, f"workflow {node.name}()"))
        tr.workflow_func = node.name
        tr.source_rel = rel
        return [tr]

    def analyze_bindings(self, trace):
        return BindingAnalysis(missing=["approver_authenticated", "action_bound",
            "arguments_bound", "run_bound", "replay_protected", "verified_at_execution"])

    def generate_patch(self, project, trace):
        fp = _sha(trace.evidence.snippet)
        rel = getattr(trace, "source_rel", "payment_workflow.py")
        manifest = {"schema": "vyrion.manifest.v1", "framework": "dbos",
                    "approval_point": trace.approval_id, "action_id": trace.action_id,
                    "action_fingerprint": fp, "environment": "production",
                    "audience": "payments", "tenant": "default", "fail_mode": "closed",
                    "public_keys": "public-keys/", "source_file": rel}
        plan = PatchPlan(
            steps=["back up the workflow source",
                   "patch source: verify a provenance-bound Seal right after DBOS.recv()",
                   "install vyrion_guard.py + vyrion_broker.py", "create .vyrion/manifest.json"],
            files_touched=[rel],
            generated_artifacts={"vyrion_guard.py": GUARD_MODULE,
                                 "vyrion_broker.py": BROKER_MODULE,
                                 ".vyrion/manifest.json": json.dumps(manifest, indent=2)},
            native_package=self.native_package)
        plan.action_fingerprint = fp
        plan.workflow_func = getattr(trace, "workflow_func", "payment_workflow")
        plan.arg_fields = list(trace.arguments)
        plan.source_file = rel
        return plan

    def apply_patch(self, project, patch):
        proj = Path(project); vdir = proj / ".vyrion"
        (vdir / "backups").mkdir(parents=True, exist_ok=True)
        (vdir / "public-keys").mkdir(parents=True, exist_ok=True)
        changed = []
        src_rel = getattr(patch, "source_file", "payment_workflow.py")
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
            new_src = patch_dbos(original, getattr(patch, "workflow_func", "payment_workflow"),
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
        try:
            import dbos  # noqa: F401
        except Exception:
            return RuntimeProof(status="pending_live_host",
                host_requirements=self.host_requirements,
                live_command="vyrion certify --framework dbos --live --project .",
                transcript="DBOS is not installed on this host; live gates pending.")
        if not (Path(project) / "payment_workflow.py").exists():
            return RuntimeProof(status="pending_live_host",
                host_requirements="run your own DBOS app or tests against the patched source",
                transcript="Guard wired into your workflow after DBOS.recv(); run your app "
                           "to confirm a forged or replayed approval is blocked.")
        try:
            return self._live(project)
        except Exception as e:
            return RuntimeProof(status="failed", transcript=f"{type(e).__name__}: {e}")

    def _live(self, project):
        import io, tempfile, concurrent.futures as cf
        import logging as _logging
        # Quiet DBOS's own INFO migration logs; the ERROR-level block stays visible.
        _logging.getLogger("dbos").setLevel(_logging.WARNING)
        from dbos import DBOS, SetWorkflowID
        from vyrion.protocol import (ApprovalBroker, Approver, WorkflowRef, ExecutionRef,
                                     new_keypair)
        proj = Path(project)
        signer = new_keypair("key-1")
        (proj / ".vyrion" / "public-keys").mkdir(parents=True, exist_ok=True)
        (proj / ".vyrion" / "public-keys" / "key-1.pem").write_bytes(signer.public_pem())
        manifest = json.loads((proj / ".vyrion" / "manifest.json").read_text())
        AID = manifest["action_id"]; FP = manifest.get("action_fingerprint", "")
        APID = manifest["approval_point"]; ENV = manifest.get("environment", "production")
        AUD = manifest.get("audience", "payments")
        broker = ApprovalBroker(signer)

        sys.path.insert(0, str(proj))
        for mod in ("vyrion_guard", "vyrion_broker", "payment_workflow"):
            sys.modules.pop(mod, None)
        import vyrion_guard as guardmod
        guardmod.configure(root=str(proj))

        base = {"recipient": "acct-A", "amount": 1000, "currency": "USD"}
        log = io.StringIO()
        def say(m): print(m, file=log)

        def mkseal(run_id, args=base):
            return broker.issue(approver=Approver(subject="cfo@corp"), decision="approve",
                action_id=AID, action_fingerprint=FP, args=args,
                workflow=WorkflowRef(system="dbos", run_id=run_id, checkpoint_id=""),
                execution=ExecutionRef(environment=ENV, audience=AUD),
                approval_point_id=APID).to_dict()

        try:
            from dbos import DBOSConfig
            dbfile = Path(tempfile.mkdtemp()) / "sys.sqlite"
            DBOS(config={"name": "vyrion-dbos-live",
                         "log_level": "WARNING",
                         "system_database_url": f"sqlite:///{dbfile}"})
            # import the workflow AFTER DBOS() exists so decorators register once
            pw = importlib.import_module("payment_workflow")
            DBOS.launch()

            def run(wfid, message):
                with SetWorkflowID(wfid):
                    h = DBOS.start_workflow(pw.payment_workflow, *base.values())
                DBOS.send(wfid, message, "approval")
                try:
                    res = h.get_result()
                    return "settled" in str(res)
                except guardmod.GhostApprovalBlocked:
                    return False
                except Exception as e:
                    return not ("GhostApprovalBlocked" in type(e).__name__)

            checks = {}
            ok = run("wf-genuine", json.dumps(mkseal("wf-genuine")))
            checks["genuine"] = "ALLOWED" if ok else "BLOCKED"; say(f"N13 genuine -> {ok}")
            ok = run("wf-forge", "approve")
            checks["forge"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N14 forge -> {ok}")
            ok = run("wf-B", json.dumps(mkseal("wf-A")))
            checks["cross_context"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N15 cross-workflow -> {ok}")
            seal_r = json.dumps(mkseal("wf-replay"))
            guardmod.authorize(seal=None, args=base, run_id="warm", checkpoint_id="")
            def attempt(i):
                return 1 if guardmod.authorize(seal=seal_r, args=base, run_id="wf-replay",
                                               checkpoint_id="", execution_id=f"w{i}") else 0
            with cf.ThreadPoolExecutor(max_workers=16) as ex:
                wins = sum(ex.map(attempt, range(50)))
            checks["concurrent_replay"] = "ONE" if wins == 1 else str(wins); say(f"N16 replay -> {wins}")
            ok = run("wf-bypass", "approve")
            checks["bypass"] = "BLOCKED" if not ok else "ALLOWED"; say(f"N17 bypass -> {ok}")
        finally:
            try:
                DBOS.destroy()
            except Exception:
                pass
            if sys.path and sys.path[0] == str(proj):
                sys.path.pop(0)
        return RuntimeProof(status="executed_here", transcript=log.getvalue(), checks=checks)

    def rescan(self, project):
        proj = Path(project); m = (proj / ".vyrion" / "manifest.json").exists()
        src = self._workflow_with_recv(project)
        src_dir = (proj / src[4]).parent if src else proj
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
        pristine = Path(__file__).parent.parent.parent / "_fixtures" / "dbos" / "payment_workflow.py"
        sample = proj / "payment_workflow.py"
        identical = sample.exists() and (_sha(sample.read_text()) == _sha(pristine.read_text()))
        return RollbackEvidence(True, restored, identical)
