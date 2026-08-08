"""Vyrion engine: detect exposed gates, protect them with the Seal, and verify."""
from .registry import build_fleet, target_for, get_adapter
from .verification import certify, GATES, GateStatus, Certification
__all__ = ["build_fleet", "target_for", "get_adapter", "certify",
           "GATES", "GateStatus", "Certification"]
