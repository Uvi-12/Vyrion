"""Native adapter for Genkit (Node/TypeScript human-in-the-loop interrupts).

Genkit gates a tool with an interrupt (defineInterrupt); on resume the approval reply
is trusted and the action runs. A writer of the persisted interrupt/resume state can
inject an approval reply with no binding to approver, action, arguments, or a single-use
nonce (the Ghost Approval surface).

Vyrion is Python, but the Seal is language-agnostic: the JS guard (vyrion_guard.mjs)
verifies the Ed25519 signature over the identical RFC 8785 canonicalization, so a
Python-minted Seal verifies in Node byte-for-byte. There is no trusted run identity in
the serialized state, so binding is action + arguments + a single-use nonce.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from ..protection.templates import GUARD_JS
from ..protection.patcher import patch_js_source
from ..contract import (ActionTrace, AppliedPatch, ApprovalPointEvidence,
                        BindingAnalysis, DetectionEvidence, NativeAdapter,
                        PatchPlan, PersistenceEvidence, RescanEvidence, ResumeEvidence,
                        RollbackEvidence, RuntimeProof, SourceEvidence)


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()[:16]


# matches: export async function NAME({ a, b, approval }) {   OR   async function NAME({...}) {
_FUNC_RE = re.compile(
    r"(?:export\s+)?async\s+function\s+(\w+)\s*\(\s*\{([^}]*)\}\s*\)\s*\{")
_IMPORT_TOKEN = "genkit"


class GenkitNativeAdapter(NativeAdapter):
    framework = "Genkit"
    native_package = "vyrion-genkit"
    host_requirements = "npm install genkit  (Node >= 18)"
    _guard_filename = "vyrion_guard.mjs"
    _sample_filename = "payment_agent.mjs"
    _sample_dir = "genkit"
    _system = "genkit"
    _approval_point = "genkit-approval"
    _framework_key = "genkit"

    def _src_files(self, project):
        skip = {".vyrion", ".git", "__pycache__", ".venv", "venv",
                "node_modules", ".mypy_cache", ".pytest_cache", "build", "dist"}
        matches = []
        for root, dirs, files in os.walk(project):
            dirs[:] = [d for d in dirs if d not in skip]
            if ".vyrion" in root or "node_modules" in root:
                continue
            for f in files:
                if f.endswith((".mjs", ".js", ".ts")):
                    matches.append(os.path.join(root, f))
        yield from sorted(matches)

    def _ev(self, path, line_no, snippet, construct):
        return SourceEvidence(path=path, start_line=line_no, end_line=line_no, language="javascript",
                              construct=construct, snippet=snippet.strip()[:120], parser="regex",
                              fingerprint=_sha(snippet), confidence="high")

    def detect_project(self, project):
        hits = []
        for path in self._src_files(project):
            text = Path(path).read_text()
            if self._import_token() in text and ("import" in text or "require" in text):
                for i, ln in enumerate(text.splitlines(), 1):
                    if self._import_token() in ln and ("import" in ln or "require" in ln):
                        hits.append(self._ev(path, i, ln, f"{self._framework_key} import"))
                        break
        return DetectionEvidence(detected=bool(hits), framework=self.framework, evidence=hits)

    def _import_token(self):
        return _IMPORT_TOKEN

    def detect_version(self, project):
        cands = [Path(project) / "node_modules" / self._framework_key / "package.json"]
        nm = self._find_node_modules(project)
        if nm:
            cands.append(Path(nm) / self._framework_key / "package.json")
        for cand in cands:
            if cand.exists():
                try:
                    return json.loads(cand.read_text()).get("version", "unknown")
                except Exception:
                    pass
        return "unknown"

    def _shape(self, project):
        """Find the protected async function with an 'approval' destructured param,
        its approval param, and its domain args. Returns
        (path, action_func, approval_param, arg_fields, source_rel)."""
        for path in self._src_files(project):
            text = Path(path).read_text()
            if "approval" not in text:
                continue
            for m in _FUNC_RE.finditer(text):
                name, params = m.group(1), m.group(2)
                parts = [p.strip() for p in params.split(",") if p.strip()]
                if "approval" in parts:
                    domain = [p for p in parts if p != "approval"]
                    return (path, name, "approval", (domain or ["amount"]),
                            os.path.relpath(path, project))
        return None

    def discover_approval_points(self, project):
        s = self._shape(project)
        if not s:
            return []
        path, action, _, _, _ = s
        return [ApprovalPointEvidence(self._approval_point, "Genkit interrupt (defineInterrupt)",
                                      self._ev(path, 1, f"interrupt gate for {action}()", "interrupt"))]

    def discover_persistence(self, project):
        return [PersistenceEvidence("Genkit interrupt/resume state", "approval reply", True)]

    def discover_resume(self, project):
        return [ResumeEvidence("generate({ resume: { respond: [...] } }) replays the approval reply")]

    def trace_actions(self, project, approval):
        s = self._shape(project)
        if not s:
            return []
        path, action, approval_param, args, rel = s
        tr = ActionTrace(approval.id, f"action.{action}", "Genkit tool",
                         args, ["approval"] + args, self._ev(path, 1, f"tool {action}()", "tool"))
        tr.action_func = action
        tr.approval_param = approval_param
        tr.source_rel = rel
        return [tr]

    def analyze_bindings(self, trace):
        return BindingAnalysis(missing=["approver_authenticated", "action_bound",
            "arguments_bound", "replay_protected", "verified_at_execution"])

    def generate_patch(self, project, trace):
        fp = _sha(trace.evidence.snippet)
        rel = getattr(trace, "source_rel", self._sample_filename)
        manifest = {"schema": "vyrion.manifest.v1", "framework": self._framework_key,
                    "approval_point": trace.approval_id, "action_id": trace.action_id,
                    "action_fingerprint": fp, "environment": "production",
                    "audience": "payments", "tenant": "default", "fail_mode": "closed",
                    "public_keys": "public-keys/", "source_file": rel}
        plan = PatchPlan(
            steps=["back up the action source",
                   "patch source: verify a provenance-bound Seal from the approval reply (JS guard)",
                   f"install {self._guard_filename}", "create .vyrion/manifest.json"],
            files_touched=[rel],
            generated_artifacts={self._guard_filename: GUARD_JS,
                                 ".vyrion/manifest.json": json.dumps(manifest, indent=2)},
            native_package=self.native_package)
        plan.action_fingerprint = fp
        plan.action_func = getattr(trace, "action_func", "transferFunds")
        plan.approval_param = getattr(trace, "approval_param", "approval")
        plan.arg_fields = list(trace.arguments)
        plan.source_file = rel
        return plan

    def apply_patch(self, project, patch):
        proj = Path(project); vdir = proj / ".vyrion"
        (vdir / "backups").mkdir(parents=True, exist_ok=True)
        (vdir / "public-keys").mkdir(parents=True, exist_ok=True)
        changed = []
        src_rel = getattr(patch, "source_file", self._sample_filename)
        src_dir = (proj / src_rel).parent
        for rel, content in patch.generated_artifacts.items():
            dest = (src_dir / rel) if rel == self._guard_filename else (proj / rel)
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
            new_src = patch_js_source(original, getattr(patch, "action_func", "transferFunds"),
                                      getattr(patch, "approval_param", "approval"),
                                      getattr(patch, "arg_fields", ["recipient", "amount", "currency"]),
                                      guard_import=self._guard_filename)
            target.write_text(new_src)
            changed.append((src_rel, _sha(original), _sha(new_src)))
            patched_any = "_vyrion_authorize" in new_src
            from vyrion.protocol import new_keypair
            signer = new_keypair("key-1")
            (vdir / "signing-key.pem").write_bytes(signer.private_pem())
            (vdir / "public-keys" / "key-1.pem").write_bytes(signer.public_pem())
        (vdir / "rollback.json").write_text(json.dumps(
            {"restore": [src_rel], "remove": [self._guard_filename, ".vyrion/"]}, indent=2))
        return AppliedPatch(changed, str(vdir / "manifest.json"), str(vdir / "backups"),
                            True, (src_dir / self._guard_filename).exists(), source_patched=patched_any)

    def _find_node_modules(self, project):
        proj = Path(project)
        cands = [proj / "node_modules"]
        env = os.environ.get("VYRION_GENKIT_NODE_MODULES") or os.environ.get("VYRION_NODE_MODULES")
        if env:
            cands.append(Path(env))
        # sandbox fallback
        cands.append(Path("/tmp/genkit_probe/node_modules"))
        for c in cands:
            if (c / self._framework_key).exists():
                return str(c)
        return None

    def verify_runtime(self, project, applied):
        if shutil.which("node") is None:
            return RuntimeProof(status="pending_live_host",
                host_requirements="install Node >= 18",
                live_command=f"vyrion certify --framework {self._framework_key} --live --project .",
                transcript="Node is not installed on this host; live gates pending.")
        nm = self._find_node_modules(project)
        if nm is None:
            return RuntimeProof(status="pending_live_host",
                host_requirements=self.host_requirements,
                live_command=f"vyrion certify --framework {self._framework_key} --live --project .",
                transcript=f"{self.framework} is not installed in a resolvable node_modules; "
                           f"run `{self.host_requirements}` in the project (or set "
                           "VYRION_GENKIT_NODE_MODULES) and re-run. The JS guard is installed "
                           "and the source is patched; live gates pending a Node host.")
        try:
            return self._live(project, nm)
        except Exception as e:
            return RuntimeProof(status="failed", transcript=f"{type(e).__name__}: {e}")

    def _live(self, project, node_modules):
        from vyrion.protocol import (ApprovalBroker, Approver, WorkflowRef, ExecutionRef, new_keypair)
        proj = Path(project)
        signer = new_keypair("key-1")
        (proj / ".vyrion" / "public-keys").mkdir(parents=True, exist_ok=True)
        (proj / ".vyrion" / "public-keys" / "key-1.pem").write_bytes(signer.public_pem())
        manifest = json.loads((proj / ".vyrion" / "manifest.json").read_text())
        AID = manifest["action_id"]; FP = manifest.get("action_fingerprint", "")
        APID = manifest["approval_point"]; ENV = manifest.get("environment", "production")
        AUD = manifest.get("audience", "payments")
        broker = ApprovalBroker(signer)
        base = {"recipient": "acct-A", "amount": 1000, "currency": "USD"}

        def mint(args=base):
            return broker.issue(approver=Approver(subject="cfo@corp"), decision="approve",
                action_id=AID, action_fingerprint=FP, args=args,
                workflow=WorkflowRef(system=self._system, run_id="", checkpoint_id=""),
                execution=ExecutionRef(environment=ENV, audience=AUD),
                approval_point_id=APID).to_dict()

        seals = {"genuine": mint(), "rebind": mint({"recipient": "acct-A", "amount": 999999, "currency": "USD"}),
                 "replay": mint()}
        (proj / "_vyrion_seals.json").write_text(json.dumps(seals))
        src_rel = manifest.get("source_file", self._sample_filename)
        runner = proj / "_vyrion_runner.mjs"
        runner.write_text(self._runner_js(src_rel))
        # ESM resolves bare specifiers via node_modules walk (NODE_PATH does not apply),
        # so make the framework resolvable by linking node_modules into the project.
        nm_link = proj / "node_modules"
        made_link = False
        if not nm_link.exists():
            try:
                os.symlink(node_modules, nm_link)
                made_link = True
            except OSError:
                pass
        try:
            out = subprocess.run(["node", str(runner)], cwd=str(proj),
                                 capture_output=True, text=True, timeout=180)
        finally:
            for f in (proj / "_vyrion_runner.mjs", proj / "_vyrion_seals.json"):
                try:
                    f.unlink()
                except OSError:
                    pass
            if made_link:
                try:
                    nm_link.unlink()
                except OSError:
                    pass
        line = next((l for l in out.stdout.splitlines() if l.startswith("VYRION_RESULTS ")), None)
        if not line:
            return RuntimeProof(status="failed", transcript=(out.stdout + "\n" + out.stderr)[-2000:])
        r = json.loads(line[len("VYRION_RESULTS "):])
        checks = {
            "genuine": "ALLOWED" if r["N13"] else "BLOCKED",
            "forge": "BLOCKED" if not r["N14"] else "ALLOWED",
            "cross_context": "BLOCKED" if not r["N15"] else "ALLOWED",
            "concurrent_replay": "ONE" if r["N16"] == 1 else str(r["N16"]),
            "bypass": "BLOCKED" if not r["N17"] else "ALLOWED",
        }
        transcript = "\n".join(f"{k} -> {v}" for k, v in checks.items())
        return RuntimeProof(status="executed_here", transcript=transcript, checks=checks)

    def _runner_js(self, src_rel):
        action = "transferFunds"
        return (
            "import * as fs from 'fs';\n"
            f"import {{ {action} }} from './{src_rel}';\n"
            "const seals = JSON.parse(fs.readFileSync('./_vyrion_seals.json','utf8'));\n"
            "const BASE = { recipient:'acct-A', amount:1000, currency:'USD' };\n"
            "async function run(approval, args=BASE){\n"
            "  try { const r = await " + action + "({ ...args, approval });\n"
            "    return String(r).includes('settled'); }\n"
            "  catch (e) { return !String(e).includes('GhostApprovalBlocked') && !String(e).includes('approval-provenance'); }\n"
            "}\n"
            "const N13 = await run(JSON.stringify(seals.genuine));\n"
            "const N14 = await run('approve');\n"
            "const N15 = await run(JSON.stringify(seals.rebind));\n"
            "let wins=0; for (let i=0;i<50;i++){ if (await run(JSON.stringify(seals.replay))) wins++; }\n"
            "const N16 = wins;\n"
            "const N17 = await run(null);\n"
            "console.log('VYRION_RESULTS ' + JSON.stringify({N13,N14,N15,N16,N17}));\n"
        )

    def rescan(self, project):
        proj = Path(project); m = (proj / ".vyrion" / "manifest.json").exists()
        s = self._shape(project)
        src_dir = (proj / s[4]).parent if s else proj
        return RescanEvidence(m, (src_dir / self._guard_filename).exists(), m,
                              [self._guard_filename, ".vyrion/manifest.json"])

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
        for mod in (self._guard_filename, "_vyrion_runner.mjs", "_vyrion_seals.json"):
            for cand in proj.rglob(mod):
                if ".vyrion" not in cand.parts:
                    try:
                        cand.unlink()
                    except OSError:
                        pass
        shutil.rmtree(vdir, ignore_errors=True)
        pristine = Path(__file__).parent.parent.parent / "_fixtures" / self._sample_dir / self._sample_filename
        sample = proj / self._sample_filename
        identical = sample.exists() and (_sha(sample.read_text()) == _sha(pristine.read_text()))
        return RollbackEvidence(True, restored, identical)
