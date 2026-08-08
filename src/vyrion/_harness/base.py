"""Base class every framework harness extends.

A harness knows one framework: how to detect it in a project, how to find its
approval points, persistence, and actions, and how each of the five techniques
maps onto that framework's specific persist-and-resume contract. Subclasses
implement discovery against real source; the base turns discovered chains into
the five-technique surface using per-framework technique descriptors.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
from typing import Optional

from .model import (ApprovalPoint, Chain, Evidence, FrameworkReport,
                    PersistencePoint, ActionPoint, SurfacePoint, Technique,
                    TechniqueSurface)

_LEDGER = json.load(open(Path(__file__).parent / "ledger_verdicts.json"))


class FrameworkHarness:
    name: str = ""
    category: str = ""
    language: str = "python"
    ledger_name: str = ""      # key into the research ledger (may differ from name)
    default_sample: str = ""   # sample project dir name under samples/

    # ---- discovery, implemented per framework -------------------------------
    def detect(self, project: str) -> bool:
        raise NotImplementedError

    def version(self, project: str) -> str:
        return "unknown"

    def discover_chains(self, project: str) -> list[Chain]:
        raise NotImplementedError

    # ---- technique surface, described per framework -------------------------
    def technique_surface(self, chain: Chain) -> list[TechniqueSurface]:
        """Default surface builder driven by per-framework descriptors.

        Subclasses set self.technique_notes: a dict keyed by Technique with
        (applicable, rationale, point-builder) so the five sections are specific
        to the framework rather than generic.
        """
        surfaces = []
        for tech in Technique:
            desc = self.technique_descriptor(tech, chain)
            surfaces.append(desc)
        return surfaces

    def technique_descriptor(self, tech: Technique, chain: Chain) -> TechniqueSurface:
        raise NotImplementedError

    # ---- report assembly ----------------------------------------------------
    def run(self, project: Optional[str] = None) -> FrameworkReport:
        project = project or self._sample_path()
        detected = self.detect(project)
        report = FrameworkReport(
            framework=self.name,
            category=self.category,
            ledger_verdicts=_LEDGER.get(self.ledger_name or self.name, {}).get("all_verdicts", {}),
            target_project=project,
            detected=detected,
            version=self.version(project) if detected else "n/a",
        )
        if not detected:
            report.notes.append(f"{self.name} not detected in {project}")
            return report
        chains = self.discover_chains(project)
        report.chains = chains
        if not chains:
            report.notes.append("framework detected but no HITL approval chain found")
            return report
        # surface is per chain; merge into per-technique sections
        merged: dict[Technique, TechniqueSurface] = {}
        for chain in chains:
            for surf in self.technique_surface(chain):
                if surf.technique not in merged:
                    merged[surf.technique] = TechniqueSurface(
                        technique=surf.technique, applicable=surf.applicable,
                        rationale=surf.rationale, points=[])
                merged[surf.technique].points.extend(surf.points)
                if surf.applicable:
                    merged[surf.technique].applicable = True
        report.surfaces = [merged[t] for t in Technique if t in merged]
        return report

    # ---- helpers ------------------------------------------------------------
    def _sample_path(self) -> str:
        return str(Path(__file__).parent / "samples" / (self.default_sample or self.name.lower()))

    @staticmethod
    def _read(path: str) -> str:
        try:
            return Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    @classmethod
    def _iter_files(cls, project: str, exts: tuple):
        if os.path.isfile(project):
            yield project
            return
        for root, _, files in os.walk(project):
            for f in files:
                if f.endswith(exts):
                    yield os.path.join(root, f)

    @staticmethod
    def _snippet(text: str, start: int, end: int) -> str:
        lines = text.splitlines()
        return "\n".join(lines[max(0, start - 1):end])[:400]

    def _evidence(self, path: str, node: ast.AST, text: str, construct: str,
                  parser: str = "python-ast") -> Evidence:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start)
        return Evidence(path=os.path.relpath(path, start=self._sample_root(path)),
                        start_line=start, end_line=end, language=self.language,
                        construct=construct, snippet=self._snippet(text, start, end),
                        parser=parser)

    @staticmethod
    def _sample_root(path: str) -> str:
        # make evidence paths relative to the samples dir when possible
        p = Path(path)
        for parent in p.parents:
            if parent.name == "samples":
                return str(parent)
        return str(Path(path).parent)
