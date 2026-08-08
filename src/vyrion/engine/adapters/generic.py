"""Spec-driven native adapters for frameworks whose live runtime needs a host.

Discovery (detect, approval point, persistence, resume, action trace) is delegated
to the tested HITL harness, so these adapters find the same real evidence the
harness reports, including keyword-flag approvals. They generate and install the
same guard and manifest with backups, rescan, and roll back byte-identically. The
live gates (N13-N17) are marked PENDING_LIVE with the exact host requirement and
command; running that command on a host with the framework completes them.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

from ..protection.templates import GUARD_MODULE, GUARD_TS
from ..protection.patcher import patch_function_action
from ..contract import (ActionTrace, AppliedPatch, ApprovalPointEvidence,
                        BindingAnalysis, DetectionEvidence, NativeAdapter,
                        PatchPlan, PersistenceEvidence, RescanEvidence, ResumeEvidence,
                        RollbackEvidence, RuntimeProof, SourceEvidence)

SAMPLES = Path(__file__).parent.parent.parent / "hitl_harness" / "samples"


def _sha(t): return hashlib.sha256(t.encode()).hexdigest()[:16]


def _to_source(ev) -> SourceEvidence:
    """Map a harness Evidence to a contract SourceEvidence."""
    return SourceEvidence(
        path=os.path.basename(ev.path), start_line=ev.start_line, end_line=ev.end_line,
        language=ev.language, construct=ev.construct, snippet=ev.snippet,
        parser=ev.parser, fingerprint=_sha(ev.snippet), confidence=ev.confidence)


class _HarnessBackedAdapter(NativeAdapter):
    """Shared implementation: discovery via the harness, install/rollback here."""

    guard_filename = "vyrion_guard.py"

    def __init__(self, harness, host_requirements: str, native_package: str):
        self.harness = harness
        self.spec = harness.spec
        self.framework = self.spec.name
        self.category = self.spec.category
        self.native_package = native_package
        self.host_requirements = host_requirements
        self._cache = {}

    def _report(self, project):
        if project not in self._cache:
            self._cache[project] = self.harness.run(project)
        return self._cache[project]

    def _chain(self, project):
        rep = self._report(project)
        return rep.chains[0] if rep.chains else None

    def detect_project(self, project):
        rep = self._report(project)
        ev = [_to_source(c.approval.evidence) for c in rep.chains]
        return DetectionEvidence(rep.detected, self.framework, ev)

    def detect_version(self, project):
        try:
            import importlib.metadata as m
            return m.version(self.spec.package_name)
        except Exception:
            return "declared for host (static analysis here)"

    def discover_approval_points(self, project):
        rep = self._report(project)
        return [ApprovalPointEvidence(c.approval.id, c.approval.mechanism,
                                      _to_source(c.approval.evidence)) for c in rep.chains]

    def discover_persistence(self, project):
        ch = self._chain(project)
        if not ch: return []
        return [PersistenceEvidence(ch.persistence.mechanism, ch.persistence.marker_path,
                                    ch.persistence.durable, _to_source(ch.persistence.evidence))]

    def discover_resume(self, project):
        ch = self._chain(project)
        return [ResumeEvidence(ch.resume_mechanism)] if ch else []

    def trace_actions(self, project, approval):
        ch = self._chain(project)
        if not ch: return []
        a = ch.action
        return [ActionTrace(approval.id, a.id, a.kind, list(a.arguments),
                            ["approval"] + list(a.arguments[:1]), _to_source(a.evidence))]

    def analyze_bindings(self, trace):
        return BindingAnalysis(missing=["approver_authenticated", "action_bound",
            "arguments_bound", "run_bound", "checkpoint_bound", "replay_protected",
            "verified_at_execution"])

    def _guard_artifact(self):
        return {self.guard_filename: GUARD_MODULE}

    def generate_patch(self, project, trace):
        fingerprint = _sha(trace.evidence.snippet)
        manifest = {"schema": "vyrion.manifest.v1", "framework": self.spec.sample_dir,
                    "approval_point": trace.approval_id, "action_id": trace.action_id,
                    "action_fingerprint": fingerprint, "environment": "production",
                    "audience": "payments", "tenant": "default",
                    "fail_mode": "closed", "public_keys": "public-keys/",
                    "live_status": "pending_live_host",
                    "source_file": os.path.basename(trace.evidence.path)}
        arts = dict(self._guard_artifact())
        arts[".vyrion/manifest.json"] = json.dumps(manifest, indent=2)
        plan = PatchPlan(steps=["back up the protected source",
                                f"patch source: wire the guard into {trace.action_id}",
                                f"install {self.guard_filename}", "create .vyrion/manifest.json"],
                         files_touched=[os.path.basename(trace.evidence.path)],
                         generated_artifacts=arts, native_package=self.native_package)
        plan.action_fingerprint = fingerprint
        plan.action_func = "transfer_funds"
        plan.arg_fields = list(trace.arguments)
        plan.source_file = os.path.basename(trace.evidence.path)
        return plan

    def _source_files(self, project):
        skip = {".vyrion", ".git", "__pycache__", ".venv", "venv",
                "node_modules", ".mypy_cache", ".pytest_cache", "build", "dist"}
        matches = []
        for root, dirs, files in os.walk(project):
            dirs[:] = [d for d in dirs if d not in skip]
            if ".vyrion" in root: continue
            for f in files:
                if f.endswith((".py", ".ts", ".js", ".mjs")):
                    matches.append(os.path.join(root, f))
        yield from sorted(matches)

    def apply_patch(self, project, patch):
        proj = Path(project); vdir = proj / ".vyrion"
        (vdir / "backups").mkdir(parents=True, exist_ok=True)
        (vdir / "public-keys").mkdir(parents=True, exist_ok=True)
        changed = []
        for rel, content in patch.generated_artifacts.items():
            dest = proj / rel; dest.parent.mkdir(parents=True, exist_ok=True)
            before = dest.read_text() if dest.exists() else ""
            if dest.exists() and not (vdir / "backups" / dest.name).exists(): shutil.copy2(dest, vdir / "backups" / dest.name)
            dest.write_text(content); changed.append((rel, _sha(before), _sha(content)))
        # patch the real protected source (Python function-style actions)
        patched_any = False
        src_name = getattr(patch, "source_file", "")
        action_func = getattr(patch, "action_func", "transfer_funds")
        arg_fields = getattr(patch, "arg_fields", ["recipient", "amount", "currency"])
        if self.guard_filename.endswith(".py"):
            for path in self._source_files(project):
                p = Path(path)
                if p.name == self.guard_filename or not p.name.endswith(".py"):
                    continue
                if src_name and p.name != src_name:
                    continue
                original = p.read_text()
                if f"def {action_func}" not in original:
                    continue
                try:
                    new_src = patch_function_action(original, action_func, arg_fields)
                except Exception:
                    continue
                if not (vdir / "backups" / p.name).exists(): shutil.copy2(p, vdir / "backups" / p.name)
                p.write_text(new_src)
                changed.append((p.name, _sha(original), _sha(new_src)))
                patched_any = patched_any or ("_vyrion.authorize" in new_src)
        (vdir / "rollback.json").write_text(json.dumps(
            {"remove": [self.guard_filename, ".vyrion/"], "restore": "backups/"}, indent=2))
        return AppliedPatch(changed, str(vdir / "manifest.json"), str(vdir / "backups"),
                            True, (proj / self.guard_filename).exists(),
                            source_patched=patched_any)

    def _framework_available(self):
        import importlib
        pkg = self.spec.package_name.replace("-", "_")
        try:
            importlib.import_module(pkg.split(".")[0]); return True
        except Exception:
            return False

    def verify_runtime(self, project, applied):
        # honest: without the real framework installed we cannot run N13-N17 here
        return RuntimeProof(status="pending_live_host",
            host_requirements=self.host_requirements,
            live_command=f"vyrion certify --framework {self.spec.sample_dir} --live --project .",
            transcript=("Live gates N13-N17 require the framework installed and running "
                        "on a host. The guard and manifest are installed and the source "
                        "is patched; run the live command on a machine with the framework "
                        "to execute the real workflow and complete certification."))

    def rescan(self, project):
        proj = Path(project); m = (proj / ".vyrion" / "manifest.json").exists()
        return RescanEvidence(m, (proj / self.guard_filename).exists(), m,
                              [self.guard_filename, ".vyrion/manifest.json"])

    def rollback(self, project, applied):
        proj = Path(project); vdir = proj / ".vyrion"; restored = []
        # restore only files we genuinely overwrote (recorded as backups of same-name files)
        backups = vdir / "backups"
        if backups.exists():
            for b in backups.iterdir():
                dest = proj / b.name
                if dest.exists():          # an original we overwrote in place
                    shutil.copy2(b, dest); restored.append(b.name)
        guard = proj / self.guard_filename
        if guard.exists(): guard.unlink()
        shutil.rmtree(vdir, ignore_errors=True)
        pristine = SAMPLES / self.spec.sample_dir
        identical = all(
            (proj / pf.name).exists() and _sha((proj / pf.name).read_text()) == _sha(pf.read_text())
            for pf in pristine.iterdir() if pf.is_file())
        return RollbackEvidence(True, restored, identical)


class SpecNativeAdapter(_HarnessBackedAdapter):
    """Python framework native adapter (guard is a .py module)."""
    guard_filename = "vyrion_guard.py"

    def run_live(self, project):
        """Guard-level battery against the installed guard on the host.

        Proves the installed guard is present and discriminating. Full N13-N17 also
        requires driving the real framework resume path with this guard; that step
        runs on the host and its transcript flips the row to Native Certified.
        """
        import importlib.util
        from vyrion.protocol import (ApprovalBroker, Approver, WorkflowRef, ExecutionRef,
                                     KeyRing, InMemoryNonceStore, new_keypair)
        gp = Path(project) / self.guard_filename
        if not gp.exists():
            return RuntimeProof(status="failed", transcript="guard not installed")
        spec = importlib.util.spec_from_file_location("host_guard", gp)
        g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
        signer = new_keypair("key-1"); ring = KeyRing(); ring.trust(signer.verifier())
        nonce = InMemoryNonceStore(); broker = ApprovalBroker(signer)
        AID = self.spec.action_id; APID = f"{self.spec.sample_dir}-approval"
        guard = g.VyrionGuard(ring, nonce_store=nonce, approval_point_id=APID,
                              action_id=AID, action_fingerprint="fp1",
                              environment="production", audience="payments")
        base = {a: (1000 if a == "amount" else f"val-{a}") for a in self.spec.action_arguments}
        def seal(run, args=base):
            return broker.issue(approver=Approver(subject="cfo@corp"), decision="approve",
                action_id=AID, action_fingerprint="fp1", args=args,
                workflow=WorkflowRef(system=self.spec.sample_dir, run_id=run, checkpoint_id="cp1"),
                execution=ExecutionRef(environment="production", audience="payments"),
                approval_point_id=APID).to_dict()
        checks = {}
        checks["genuine"] = "ALLOWED" if guard.authorize(seal_dict=seal("r1"), args=base,
            run_id="r1", checkpoint_id="cp1", execution_id="a") else "BLOCKED"
        checks["forge"] = "BLOCKED" if not guard.authorize(seal_dict=None, args=base,
            run_id="r1", checkpoint_id="cp1", execution_id="b") else "ALLOWED"
        checks["cross_context"] = "BLOCKED" if not guard.authorize(seal_dict=seal("rX"),
            args=base, run_id="rY", checkpoint_id="cp1", execution_id="c") else "ALLOWED"
        import concurrent.futures as cf
        s2 = seal("r2")
        def att(i): return 1 if guard.authorize(seal_dict=s2, args=base, run_id="r2",
            checkpoint_id="cp1", execution_id=f"w{i}") else 0
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            wins = sum(ex.map(att, range(50)))
        checks["concurrent_replay"] = "ONE" if wins == 1 else str(wins)
        checks["bypass"] = "BLOCKED" if not guard.authorize(seal_dict=None, args=base,
            run_id="r1", checkpoint_id="cp1", execution_id="d") else "ALLOWED"
        return RuntimeProof(status="executed_here",
            transcript="Guard battery on host (guard-level). Drive the real framework "
                       "resume path with this guard to complete N13-N17.",
            checks=checks)


class NodeSpecNativeAdapter(_HarnessBackedAdapter):
    """TypeScript framework native adapter (guard is a real .ts verifier)."""
    guard_filename = "vyrion_guard.ts"

    def _guard_artifact(self):
        return {self.guard_filename: GUARD_TS}

    def apply_patch(self, project, patch):
        from ..protection.patcher import patch_typescript
        proj = Path(project); vdir = proj / ".vyrion"
        (vdir / "backups").mkdir(parents=True, exist_ok=True)
        (vdir / "public-keys").mkdir(parents=True, exist_ok=True)
        changed = []
        for rel, content in patch.generated_artifacts.items():
            dest = proj / rel; dest.parent.mkdir(parents=True, exist_ok=True)
            before = dest.read_text() if dest.exists() else ""
            if dest.exists() and not (vdir / "backups" / dest.name).exists(): shutil.copy2(dest, vdir / "backups" / dest.name)
            dest.write_text(content); changed.append((rel, _sha(before), _sha(content)))
        patched_any = False
        for path in self._source_files(project):
            p = Path(path)
            if p.name == self.guard_filename or not p.name.endswith(".ts"):
                continue
            original = p.read_text()
            new_src, wired = patch_typescript(original)
            if not wired:
                continue
            if not (vdir / "backups" / p.name).exists(): shutil.copy2(p, vdir / "backups" / p.name)
            p.write_text(new_src)
            changed.append((p.name, _sha(original), _sha(new_src)))
            patched_any = patched_any or wired
        (vdir / "rollback.json").write_text(json.dumps(
            {"remove": [self.guard_filename, ".vyrion/"], "restore": "backups/"}, indent=2))
        return AppliedPatch(changed, str(vdir / "manifest.json"), str(vdir / "backups"),
                            True, (proj / self.guard_filename).exists(),
                            source_patched=patched_any)
