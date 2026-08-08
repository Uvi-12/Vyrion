"""Vyrion HITL Attack-Surface Harness.

For a target project of a supported framework, the harness discovers the real
human-approval points, the real persistence boundary, and the real resume path,
traces each approval to the action it authorizes, and reports every point at
which each of the five provenance techniques (Forge, Rebind, Replay, Suppress,
Launder) could land. It parses real source (Python or TypeScript AST, workflow
JSON/YAML) and returns concrete evidence: file, line, construct. It does not run
the live framework; the live-runtime proof is produced separately and folded in
to reach Native Certified.
"""

from .model import (Technique, SurfacePoint, TechniqueSurface, ApprovalPoint,
                    PersistencePoint, ActionPoint, Chain, Evidence, FrameworkReport)
from .base import FrameworkHarness
from .registry import ALL_HARNESSES, get_harness, run_all

__all__ = [
    "Technique", "SurfacePoint", "TechniqueSurface", "ApprovalPoint",
    "PersistencePoint", "ActionPoint", "Chain", "Evidence", "FrameworkReport",
    "FrameworkHarness", "ALL_HARNESSES", "get_harness", "run_all",
]
