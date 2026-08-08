"""Guard and broker source templates installed into protected projects.

These are read as text and written next to the protected action; the guard holds
public verification keys only and fails closed.
"""
from pathlib import Path

_HERE = Path(__file__).parent
GUARD_MODULE = (_HERE / "python_guard.py").read_text()
BROKER_MODULE = (_HERE / "python_broker.py").read_text()
GUARD_JS = (_HERE / "node_guard.mjs").read_text()
GUARD_TS = (_HERE / "node_guard.ts").read_text() if (_HERE / "node_guard.ts").exists() else GUARD_JS
__all__ = ["GUARD_MODULE", "BROKER_MODULE", "GUARD_JS", "GUARD_TS"]
