"""Node/TypeScript agent-framework harness.

Python has no bundled TypeScript parser, so discovery uses anchored regular
expressions with real line tracking to produce genuine source evidence (file,
line, construct) for the approval primitive and the protected tool. Sufficient
for Genkit and Vercel AI SDK whose HITL markers are distinctive call sites.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .base import FrameworkHarness
from .model import (ApprovalPoint, ActionPoint, Chain, Evidence, PersistencePoint,
                    Technique, TechniqueSurface)
from .surface import build_surface


@dataclass
class NodeSpec:
    name: str
    category: str
    ledger_name: str
    detect_patterns: list
    approval_patterns: list        # (regex, construct-label)
    action_patterns: list
    approval_mechanism: str
    persistence_mechanism: str
    marker_path: str
    resume_mechanism: str
    action_id: str = "transferFunds"
    action_arguments: list = field(default_factory=lambda: ["recipient", "amount", "currency"])
    resistant: dict = field(default_factory=dict)
    sample_dir: str = ""


class NodeAgentHarness(FrameworkHarness):
    language = "typescript"

    def __init__(self, spec: NodeSpec):
        self.spec = spec
        self.name = spec.name
        self.category = spec.category
        self.ledger_name = spec.ledger_name
        self.default_sample = spec.sample_dir or spec.name.lower().replace(" ", "_")

    def detect(self, project: str) -> bool:
        for path in self._iter_files(project, (".ts", ".js", ".tsx")):
            text = self._read(path)
            if any(re.search(p, text) for p in self.spec.detect_patterns):
                return True
        return False

    def version(self, project: str) -> str:
        return "not installed (static analysis only)"

    def _match_ev(self, path, text, pattern, construct) -> Evidence | None:
        m = re.search(pattern, text)
        if not m:
            return None
        line = text[:m.start()].count("\n") + 1
        snippet = text.splitlines()[line - 1].strip() if line <= len(text.splitlines()) else ""
        import os
        rel = path
        for parent in __import__("pathlib").Path(path).parents:
            if parent.name == "samples":
                rel = os.path.relpath(path, str(parent)); break
        return Evidence(path=rel, start_line=line, end_line=line, language="typescript",
                        construct=construct, snippet=snippet[:400], parser="typescript-regex")

    def discover_chains(self, project: str) -> list[Chain]:
        chains = []
        for path in self._iter_files(project, (".ts", ".js", ".tsx")):
            text = self._read(path)
            if not any(re.search(p, text) for p in self.spec.detect_patterns):
                continue
            approval_ev = None
            for pat, label in self.spec.approval_patterns:
                approval_ev = self._match_ev(path, text, pat, label)
                if approval_ev:
                    break
            if not approval_ev:
                continue
            action_ev = None
            for pat, label in self.spec.action_patterns:
                action_ev = self._match_ev(path, text, pat, label)
                if action_ev:
                    break
            action_ev = action_ev or approval_ev
            approval = ApprovalPoint(id=f"{self.spec.name.lower().split()[0]}-approval",
                                     mechanism=self.spec.approval_mechanism,
                                     evidence=approval_ev,
                                     persists_via=self.spec.persistence_mechanism)
            persistence = PersistencePoint(mechanism=self.spec.persistence_mechanism,
                                           marker_path=self.spec.marker_path,
                                           evidence=approval_ev, durable=True)
            action = ActionPoint(id=self.spec.action_id, kind="tool invocation",
                                 arguments=self.spec.action_arguments, evidence=action_ev)
            chains.append(Chain(approval=approval, persistence=persistence, action=action,
                                resume_mechanism=self.spec.resume_mechanism))
        return chains

    def technique_surface(self, chain: Chain) -> list[TechniqueSurface]:
        resistant = {Technique(k): v for k, v in self.spec.resistant.items()} \
            if self.spec.resistant else {}
        return build_surface(chain, resistant=resistant)

    def technique_descriptor(self, tech, chain):
        raise NotImplementedError
