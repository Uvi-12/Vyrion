"""Python agent-framework harness base.

Configured with the framework's detection imports, approval primitives,
persistence label and marker, and action markers. Discovers real chains from a
target project via the shared AST scanner, then builds the five-technique surface.
Frameworks that resist a technique (server-owned authority) pass a resistant map.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from .base import FrameworkHarness
from .model import (ApprovalPoint, ActionPoint, Chain, Evidence, PersistencePoint,
                    Technique, TechniqueSurface)
from .pyast import imports_any, scan_python
from .surface import build_surface


@dataclass
class AgentSpec:
    name: str
    category: str
    ledger_name: str
    detect_imports: set
    approval_calls: set = field(default_factory=set)
    approval_kwflags: set = field(default_factory=set)
    approval_defs: set = field(default_factory=set)
    action_decorators: set = field(default_factory=set)
    action_calls: set = field(default_factory=set)
    action_defs: set = field(default_factory=lambda: {"transfer_funds"})
    approval_mechanism: str = "human approval"
    persistence_mechanism: str = "persisted workflow state"
    marker_path: str = "approval"
    resume_mechanism: str = "resume from persisted state"
    action_id: str = "protected.action"
    action_arguments: list = field(default_factory=lambda: ["recipient", "amount", "currency"])
    package_name: str = ""
    resistant: dict = field(default_factory=dict)
    sample_dir: str = ""


class PyAgentHarness(FrameworkHarness):
    language = "python"

    def __init__(self, spec: AgentSpec):
        self.spec = spec
        self.name = spec.name
        self.category = spec.category
        self.ledger_name = spec.ledger_name
        self.default_sample = spec.sample_dir or spec.name.lower().replace(" ", "_")

    def detect(self, project: str) -> bool:
        for path in self._iter_files(project, (".py",)):
            if imports_any(self._read(path), self.spec.detect_imports):
                return True
        return False

    def version(self, project: str) -> str:
        if not self.spec.package_name:
            return "unknown"
        try:
            import importlib.metadata as m
            return m.version(self.spec.package_name)
        except Exception:
            return "not installed (static analysis only)"

    def discover_chains(self, project: str) -> list[Chain]:
        chains: list[Chain] = []
        for path in self._iter_files(project, (".py",)):
            text = self._read(path)
            if not imports_any(text, self.spec.detect_imports):
                continue
            sc = scan_python(path, text,
                             call_names=self.spec.approval_calls,
                             kw_flags=self.spec.approval_kwflags,
                             decorator_names=self.spec.action_decorators,
                             action_call_names=self.spec.action_calls,
                             approval_def_names=self.spec.approval_defs,
                             action_def_names=self.spec.action_defs)
            if not sc.approvals:
                continue
            ap_hit = sc.approvals[0]
            approval_ev = self._evidence(ap_hit.path, ap_hit.node, ap_hit.text, ap_hit.construct)
            action_ev = None
            if sc.actions:
                a = sc.actions[0]
                action_ev = self._evidence(a.path, a.node, a.text, a.construct)
            if action_ev is None:
                action_ev = approval_ev
            approval = ApprovalPoint(
                id=f"{self.spec.name.lower().split()[0]}-approval",
                mechanism=self.spec.approval_mechanism,
                evidence=approval_ev,
                persists_via=self.spec.persistence_mechanism)
            persistence = PersistencePoint(
                mechanism=self.spec.persistence_mechanism,
                marker_path=self.spec.marker_path,
                evidence=approval_ev, durable=True)
            action = ActionPoint(
                id=self.spec.action_id, kind="tool/function invocation",
                arguments=self.spec.action_arguments, evidence=action_ev)
            chains.append(Chain(approval=approval, persistence=persistence,
                                action=action, resume_mechanism=self.spec.resume_mechanism))
        return chains

    def technique_surface(self, chain: Chain) -> list[TechniqueSurface]:
        resistant = {Technique(k): v for k, v in self.spec.resistant.items()} \
            if self.spec.resistant else {}
        return build_surface(chain, resistant=resistant)

    def technique_descriptor(self, tech, chain):  # not used; surface built directly
        raise NotImplementedError
