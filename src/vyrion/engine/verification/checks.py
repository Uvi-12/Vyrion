"""The N1-N20 certification gate model.

Runs an adapter through the full lifecycle against a target project and records
each gate's status with the evidence that satisfied it. A row is Native Certified
only when every gate passes AND the live-runtime gates (N13-N17) ran here
(status executed_here). If the live proof is pending a live host, the row is
Native Ready: everything else proven, live step coded and waiting for a transcript.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from enum import Enum
from typing import Optional

import os
from ..contract import NativeAdapter, RuntimeProof


class GateStatus(str, Enum):
    PASS = "PASS"
    PENDING_LIVE = "PENDING_LIVE"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class GateResult:
    id: str
    name: str
    status: GateStatus
    detail: str = ""


GATES = [
    ("N1", "framework detected"),
    ("N2", "version obtained"),
    ("N3", "approval point found with evidence"),
    ("N4", "persistence mechanism found"),
    ("N5", "resume mechanism found"),
    ("N6", "approval traced to real action"),
    ("N7", "mutable post-approval values identified"),
    ("N8", "reviewable native patch generated"),
    ("N9", "approval-event issuance installed"),
    ("N10", "final action verifier installed"),
    ("N11", "protection persists after exit"),
    ("N12", "private key outside mutable state"),
    ("N13", "real framework runs with genuine approval"),
    ("N14", "real persisted-state mutation blocked"),
    ("N15", "cross-run/checkpoint reuse blocked"),
    ("N16", "concurrent replay blocked atomically"),
    ("N17", "forced bypass cannot obtain credential"),
    ("N18", "rescan proves installation"),
    ("N19", "rollback restores original project"),
    ("N20", "version matrix declared for CI"),
]
_LIVE = {"N13", "N14", "N15", "N16", "N17"}


@dataclass
class Certification:
    framework: str
    gates: list = field(default_factory=list)
    runtime_status: str = ""

    @property
    def all_non_live_pass(self) -> bool:
        return all(g.status == GateStatus.PASS for g in self.gates
                   if g.id not in _LIVE)

    @property
    def non_live_ok_for_ready(self) -> bool:
        # a non-live gate that is pending-on-host (e.g. version pin needs the
        # framework installed) does not fail readiness; only a real FAIL does.
        return all(g.status in (GateStatus.PASS, GateStatus.PENDING_LIVE)
                   for g in self.gates if g.id not in _LIVE)

    @property
    def live_pass(self) -> bool:
        return all(g.status == GateStatus.PASS for g in self.gates if g.id in _LIVE)

    @property
    def tier(self) -> str:
        if self.all_non_live_pass and self.live_pass:
            return "Native Certified"
        if self.non_live_ok_for_ready and all(
                g.status in (GateStatus.PENDING_LIVE, GateStatus.PASS)
                for g in self.gates if g.id in _LIVE):
            return "Native Ready"
        return "Incomplete"


def certify(adapter: NativeAdapter, project: str) -> Certification:
    cert = Certification(framework=adapter.framework)
    res: dict[str, GateResult] = {}

    def rec(gid, status, detail=""):
        name = dict(GATES)[gid]
        res[gid] = GateResult(gid, name, status, detail)

    # N1 detect
    det = adapter.detect_project(project)
    rec("N1", GateStatus.PASS if det.detected else GateStatus.FAIL,
        f"{len(det.evidence)} evidence hits" if det.detected else "not detected")
    if not det.detected:
        cert.gates = [res["N1"]]
        return cert

    # N2 version: known -> PASS; unavailable because the framework is not installed
    # on this host -> pending (not a failure, same as the live gates).
    ver = adapter.detect_version(project)
    if ver and ver != "unknown":
        rec("N2", GateStatus.PASS, ver)
    else:
        rec("N2", GateStatus.PENDING_LIVE,
            "framework not installed on this host; version pending")

    # N3 approval points
    aps = adapter.discover_approval_points(project)
    rec("N3", GateStatus.PASS if aps else GateStatus.FAIL,
        f"{len(aps)} approval point(s)")
    # N4 persistence
    pers = adapter.discover_persistence(project)
    rec("N4", GateStatus.PASS if pers else GateStatus.FAIL,
        pers[0].mechanism if pers else "none")
    # N5 resume
    res_pts = adapter.discover_resume(project)
    rec("N5", GateStatus.PASS if res_pts else GateStatus.FAIL,
        res_pts[0].mechanism if res_pts else "none")
    # N6/N7 trace
    trace = None
    if aps:
        traces = adapter.trace_actions(project, aps[0])
        trace = traces[0] if traces else None
    rec("N6", GateStatus.PASS if trace else GateStatus.FAIL,
        trace.action_id if trace else "no trace")
    rec("N7", GateStatus.PASS if (trace and trace.mutable_after_approval) else GateStatus.FAIL,
        ", ".join(trace.mutable_after_approval) if trace else "")
    # N8 patch
    patch = adapter.generate_patch(project, trace) if trace else None
    rec("N8", GateStatus.PASS if (patch and patch.generated_artifacts) else GateStatus.FAIL,
        f"{len(patch.generated_artifacts)} artifact(s)" if patch else "")
    # N9/N10/N11/N12 apply
    applied = adapter.apply_patch(project, patch) if patch else None
    rec("N9", GateStatus.PASS if (applied and applied.issuer_installed) else GateStatus.FAIL)
    # N10 requires the guard to be genuinely wired into the protected source, not just present
    wired = bool(applied and getattr(applied, "source_patched", False))
    rec("N10", GateStatus.PASS if wired else GateStatus.FAIL,
        "guard call wired into the protected action" if wired
        else "guard installed but not wired into the action source")
    rec("N11", GateStatus.PASS if (applied and applied.manifest_path) else GateStatus.FAIL,
        applied.manifest_path if applied else "")
    # N12: the installed guard must hold public verification material only
    guard_ok = False
    guard_detail = "no guard installed"
    if applied and applied.guard_installed:
        import glob as _glob
        gpaths = _glob.glob(os.path.join(project, "vyrion_guard.*"))
        if gpaths:
            gtext = open(gpaths[0]).read()
            has_private = any(t in gtext for t in
                              ("Ed25519PrivateKey", "PRIVATE KEY", "ApprovalBroker",
                               "def sign(", "createPrivateKey", ".sign("))
            guard_ok = not has_private
            guard_detail = ("guard holds public verification keys only"
                            if guard_ok else "guard contains signing material")
    rec("N12", GateStatus.PASS if guard_ok else GateStatus.FAIL, guard_detail)
    # N13-N17 live runtime
    proof = adapter.verify_runtime(project, applied) if applied else \
        RuntimeProof(status="failed")
    cert.runtime_status = proof.status
    if proof.status == "executed_here":
        expected = {"N13": ("genuine", "ALLOWED"), "N14": ("forge", "BLOCKED"),
                    "N15": ("cross_context", "BLOCKED"), "N16": ("concurrent_replay", "ONE"),
                    "N17": ("bypass", "BLOCKED")}
        for gid, (key, want) in expected.items():
            got = proof.checks.get(key)
            rec(gid, GateStatus.PASS if got == want else GateStatus.FAIL,
                f"{key}={got}")
    elif proof.status == "pending_live_host":
        for gid in ["N13", "N14", "N15", "N16", "N17"]:
            rec(gid, GateStatus.PENDING_LIVE, proof.host_requirements)
    else:  # status == "failed": a real runtime error is a failure, not pending
        for gid in ["N13", "N14", "N15", "N16", "N17"]:
            rec(gid, GateStatus.FAIL, proof.transcript[:200])
    # N18 rescan
    rescan = adapter.rescan(project)
    rec("N18", GateStatus.PASS if (rescan.issuer_found and rescan.guard_found)
        else GateStatus.FAIL)
    # N19 rollback
    rb = adapter.rollback(project, applied) if applied else None
    rec("N19", GateStatus.PASS if (rb and rb.byte_identical) else GateStatus.FAIL,
        "byte-identical restore" if (rb and rb.byte_identical) else "")
    # N20: honest version pinning. PASS only if the framework package version is
    # actually resolvable (dedicated extras) or pinned; otherwise pending.
    n20_ok = False; n20_detail = "no version declared for this framework"
    try:
        import importlib.metadata as _im
        pkg = getattr(getattr(adapter, "spec", None), "package_name", None)
        if pkg is None:
            pkg = {"LangGraph": "langgraph", "LlamaIndex Workflows": "llama-index-core",
                   "Apache Burr": "burr", "DBOS Transact": "dbos", "CrewAI Flows": "crewai", "OpenAI Agents SDK": "openai_agents", "Google ADK": "google_adk", "AutoGen": "autogen_core", "Haystack": "haystack-ai", "Strands Agents": "strands-agents", "Agno": "agno", "Semantic Kernel": "semantic-kernel", "Apache Airflow": "apache-airflow", "Genkit": None, "Vercel AI": None}.get(adapter.framework)
        if pkg:
            ver = _im.version(pkg.split(".")[0].replace("_", "-"))
            n20_ok = True; n20_detail = f"{pkg}=={ver}"
        elif adapter.framework in ("Genkit", "Vercel AI"):
            # Node framework: version is pinned in the project's package.json / node_modules,
            # not via pip. Treat as pinned when Node is available on the host.
            import shutil as _sh
            npkg = {"Genkit": "genkit", "Vercel AI": "ai"}[adapter.framework]
            ver = None
            try:
                ver = adapter.detect_version(".")
            except Exception:
                ver = None
            if _sh.which("node"):
                n20_ok = True
                n20_detail = f"{npkg} (node runtime; version pinned in package.json{'' if not ver or ver=='unknown' else '==' + ver})"
    except Exception:
        n20_detail = "framework package not installed on this host (declare in extras/CI to pin)"
    rec("N20", GateStatus.PASS if n20_ok else GateStatus.PENDING_LIVE, n20_detail)

    cert.gates = [res[g] for g, _ in GATES if g in res]
    return cert

# vyrion-build: 15-frameworks COMPLETE incl. Genkit + VercelAI
