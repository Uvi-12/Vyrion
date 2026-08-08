"""The native adapter contract and its evidence types.

No method has a default no-op. Every method returns an evidence object grounded in
the real project or the real runtime. Adapters that cannot run the live framework
in this environment return a RuntimeProof with status 'pending_live_host' and the
exact command to complete it, rather than a fabricated pass.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Literal, Optional


@dataclass
class SourceEvidence:
    path: str
    start_line: int
    end_line: int
    language: str
    construct: str
    snippet: str
    parser: str
    fingerprint: str = ""
    confidence: str = "high"


@dataclass
class DetectionEvidence:
    detected: bool
    framework: str
    evidence: list = field(default_factory=list)     # SourceEvidence
    dependency_evidence: str = ""                     # e.g. requirement/lock line


@dataclass
class ApprovalPointEvidence:
    id: str
    mechanism: str
    evidence: SourceEvidence


@dataclass
class PersistenceEvidence:
    mechanism: str
    marker_path: str
    durable: bool
    evidence: Optional[SourceEvidence] = None


@dataclass
class ResumeEvidence:
    mechanism: str
    evidence: Optional[SourceEvidence] = None


@dataclass
class ActionTrace:
    approval_id: str
    action_id: str
    action_kind: str
    arguments: list
    mutable_after_approval: list
    evidence: SourceEvidence


@dataclass
class BindingAnalysis:
    missing: list = field(default_factory=list)
    present: list = field(default_factory=list)


@dataclass
class PatchPlan:
    steps: list = field(default_factory=list)
    files_touched: list = field(default_factory=list)
    generated_artifacts: dict = field(default_factory=dict)   # path -> content
    native_package: str = ""


@dataclass
class AppliedPatch:
    changed_files: list = field(default_factory=list)         # (path, before_sha, after_sha)
    manifest_path: str = ""
    backup_dir: str = ""
    issuer_installed: bool = False
    guard_installed: bool = False
    source_patched: bool = False


@dataclass
class RuntimeProof:
    status: Literal["executed_here", "pending_live_host", "failed"]
    transcript: str = ""
    checks: dict = field(default_factory=dict)                # case -> ALLOWED/BLOCKED
    live_command: str = ""
    host_requirements: str = ""


@dataclass
class RescanEvidence:
    issuer_found: bool
    guard_found: bool
    manifest_found: bool
    evidence: list = field(default_factory=list)


@dataclass
class RollbackEvidence:
    restored: bool
    files_restored: list = field(default_factory=list)
    byte_identical: bool = False


class NativeAdapter(abc.ABC):
    framework: str = ""
    category: str = ""
    language: str = "python"
    native_package: str = ""

    @abc.abstractmethod
    def detect_project(self, project: str) -> DetectionEvidence: ...

    @abc.abstractmethod
    def detect_version(self, project: str) -> str: ...

    @abc.abstractmethod
    def discover_approval_points(self, project: str) -> list: ...

    @abc.abstractmethod
    def discover_persistence(self, project: str) -> list: ...

    @abc.abstractmethod
    def discover_resume(self, project: str) -> list: ...

    @abc.abstractmethod
    def trace_actions(self, project: str, approval: ApprovalPointEvidence) -> list: ...

    @abc.abstractmethod
    def analyze_bindings(self, trace: ActionTrace) -> BindingAnalysis: ...

    @abc.abstractmethod
    def generate_patch(self, project: str, trace: ActionTrace) -> PatchPlan: ...

    @abc.abstractmethod
    def apply_patch(self, project: str, patch: PatchPlan) -> AppliedPatch: ...

    @abc.abstractmethod
    def verify_runtime(self, project: str, applied: AppliedPatch) -> RuntimeProof: ...

    @abc.abstractmethod
    def rescan(self, project: str) -> RescanEvidence: ...

    @abc.abstractmethod
    def rollback(self, project: str, applied: AppliedPatch) -> RollbackEvidence: ...
