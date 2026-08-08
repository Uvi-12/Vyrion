"""Evidence and surface data model for the harness.

Everything the harness reports is grounded in a piece of source Evidence. A
FrameworkReport carries the discovered chains and, for each of the five
techniques, the concrete points where that technique could land, each with the
payload shape an attacker would write and the binding that would defeat it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Technique(str, Enum):
    FORGE = "Forge"
    REBIND = "Rebind"
    REPLAY = "Replay"
    SUPPRESS = "Suppress"
    LAUNDER = "Launder"


@dataclass
class Evidence:
    """A concrete source location. Never synthesized; only emitted when found."""
    path: str
    start_line: int
    end_line: int
    language: str
    construct: str          # e.g. "interrupt() call", "needs_approval=True kwarg"
    snippet: str
    parser: str             # e.g. "python-ast", "typescript-regex", "workflow-json"
    confidence: str = "high"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ApprovalPoint:
    id: str
    mechanism: str          # framework-specific: interrupt, needs_approval, HITLOperator...
    evidence: Evidence
    persists_via: str = ""  # short label of where the decision is stored


@dataclass
class PersistencePoint:
    mechanism: str          # checkpointer, RunState json, XCom, session store...
    marker_path: str        # where inside the stored doc the decision lives
    evidence: Optional[Evidence] = None
    durable: bool = True


@dataclass
class ActionPoint:
    id: str
    kind: str               # tool call, operator, HTTP node, function invocation
    arguments: list[str]
    evidence: Evidence


@dataclass
class Chain:
    approval: ApprovalPoint
    persistence: PersistencePoint
    action: ActionPoint
    resume_mechanism: str
    confidence: str = "high"


@dataclass
class SurfacePoint:
    """One concrete place a technique could land, with the attacker payload and fix."""
    location: str           # human-readable: file:line or store path
    evidence: Optional[Evidence]
    attacker_writes: str    # the payload shape the attacker forges/replays/etc.
    why_it_works: str       # the missing binding that lets it through today
    binding_that_defeats_it: str  # what the Seal binds to close it


@dataclass
class TechniqueSurface:
    technique: Technique
    applicable: bool
    rationale: str          # why this technique does or does not apply to this chain
    points: list[SurfacePoint] = field(default_factory=list)


@dataclass
class FrameworkReport:
    framework: str
    category: str
    ledger_verdicts: dict           # from the research ledgers, per technique
    target_project: str
    detected: bool
    version: str
    chains: list[Chain] = field(default_factory=list)
    surfaces: list[TechniqueSurface] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "category": self.category,
            "ledger_verdicts": self.ledger_verdicts,
            "target_project": self.target_project,
            "detected": self.detected,
            "version": self.version,
            "chains": [
                {
                    "approval": {"id": c.approval.id, "mechanism": c.approval.mechanism,
                                 "evidence": c.approval.evidence.to_dict(),
                                 "persists_via": c.approval.persists_via},
                    "persistence": {"mechanism": c.persistence.mechanism,
                                    "marker_path": c.persistence.marker_path,
                                    "durable": c.persistence.durable,
                                    "evidence": c.persistence.evidence.to_dict() if c.persistence.evidence else None},
                    "action": {"id": c.action.id, "kind": c.action.kind,
                               "arguments": c.action.arguments,
                               "evidence": c.action.evidence.to_dict()},
                    "resume_mechanism": c.resume_mechanism,
                    "confidence": c.confidence,
                }
                for c in self.chains
            ],
            "surfaces": [
                {
                    "technique": s.technique.value,
                    "applicable": s.applicable,
                    "rationale": s.rationale,
                    "points": [
                        {"location": p.location,
                         "evidence": p.evidence.to_dict() if p.evidence else None,
                         "attacker_writes": p.attacker_writes,
                         "why_it_works": p.why_it_works,
                         "binding_that_defeats_it": p.binding_that_defeats_it}
                        for p in s.points
                    ],
                }
                for s in self.surfaces
            ],
            "notes": self.notes,
        }
