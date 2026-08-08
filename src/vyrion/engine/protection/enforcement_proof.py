"""Universal enforcement proof (Level 1).

After ``vyrion apply`` installs the guard and broker into a real project, this
exercises the five provenance gates directly against that installed guard and
broker, using the project's own manifest (its real action id, action
fingerprint, approval point, audience, and environment).

It runs no framework node, needs no model key, and never reaches an interrupt,
so it proves the same thing for every supported framework: the fifteen adapters
differ in how they detect and patch a workflow, but they all install one guard,
one broker, and one Seal protocol. This proof tests that shared enforcement
boundary against the repo's real action identity.

The five gates:

    genuine        a Seal minted for this action and run verifies            -> ALLOWED
    forged         no Seal at all is rejected                                -> BLOCKED
    cross_context  a Seal minted for another run is rejected                 -> BLOCKED
    replayed       a Seal already consumed once is rejected the second time  -> BLOCKED
    arg_tampered   a genuine Seal replayed against different arguments        -> BLOCKED

A run passes only if the genuine gate is ALLOWED and all four attacks are BLOCKED.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path


GATE_ORDER = ["genuine", "forged", "cross_context", "replayed", "arg_tampered"]

# A stable run id and a representative argument set. The specific values do not
# matter; what is proven is the binding, that the same Seal ceases to authorize
# the moment the run or the arguments change, and cannot be used twice.
_RUN_A = "vyrion-proof-run-A"
_RUN_B = "vyrion-proof-run-B"
_ARGS = {"vyrion_proof_arg": "canonical-value"}
_ARGS_TAMPERED = {"vyrion_proof_arg": "tampered-value"}


class ProofUnavailable(Exception):
    """Raised when the installed guard/broker cannot be loaded from the project."""


def _find_guard_dir(project: str) -> Path:
    """Locate the directory holding the installed vyrion_guard.py."""
    proj = Path(project).resolve()
    candidates = list(proj.rglob("vyrion_guard.py"))
    # Prefer one that sits beside a broker and a .vyrion manifest.
    for c in candidates:
        d = c.parent
        if (d / "vyrion_broker.py").exists():
            return d
    if candidates:
        return candidates[0].parent
    raise ProofUnavailable("vyrion_guard.py not found under the project; apply first")


def _load_guard_broker(project: str):
    guard_dir = _find_guard_dir(project)
    sys.path.insert(0, str(guard_dir))
    for mod in ("vyrion_guard", "vyrion_broker"):
        sys.modules.pop(mod, None)
    try:
        guard = importlib.import_module("vyrion_guard")
        broker = importlib.import_module("vyrion_broker")
    except Exception as exc:  # pragma: no cover - defensive
        raise ProofUnavailable(f"could not import installed guard/broker: {exc}") from exc
    # Point both at this project's manifest and keys.
    if hasattr(guard, "configure"):
        guard.configure(root=str(guard_dir))
    if hasattr(broker, "configure"):
        broker.configure(root=str(guard_dir))
    return guard, broker


def prove_enforcement(project: str) -> tuple[dict, bool]:
    """Run the five gates against the installed guard/broker.

    Returns (results, passed) where results maps each gate name to a verdict
    string ("ALLOWED"/"BLOCKED", or an "(!)"-suffixed value if it went the wrong
    way). ``passed`` is True only when enforcement held on every gate.
    """
    guard, broker = _load_guard_broker(project)

    def authorize(seal, args, run_id, execution_id):
        return bool(guard.authorize(
            seal=seal, args=args, run_id=run_id, checkpoint_id="",
            execution_id=execution_id))

    results: dict[str, str] = {}

    # 1. genuine: mint for run A + args, verify against the same -> ALLOWED
    seal = broker.mint(run_id=_RUN_A, args=_ARGS)
    ok = authorize(seal, _ARGS, _RUN_A, "proof-genuine")
    results["genuine"] = "ALLOWED" if ok else "BLOCKED(!)"

    # 2. forged: no Seal -> BLOCKED
    ok = authorize(None, _ARGS, _RUN_A, "proof-forged")
    results["forged"] = "BLOCKED" if not ok else "ALLOWED(!)"

    # 3. cross_context: Seal minted for run A, presented under run B -> BLOCKED
    seal_a = broker.mint(run_id=_RUN_A, args=_ARGS)
    ok = authorize(seal_a, _ARGS, _RUN_B, "proof-cross")
    results["cross_context"] = "BLOCKED" if not ok else "ALLOWED(!)"

    # 4. replayed: one Seal consumed twice -> first ALLOWED, second BLOCKED
    seal_r = broker.mint(run_id=_RUN_A, args=_ARGS)
    first = authorize(seal_r, _ARGS, _RUN_A, "proof-replay-1")
    second = authorize(seal_r, _ARGS, _RUN_A, "proof-replay-2")
    results["replayed"] = "BLOCKED" if (first and not second) else "ALLOWED(!)"

    # 5. arg_tampered: genuine Seal, different arguments at execution -> BLOCKED
    seal_t = broker.mint(run_id=_RUN_A, args=_ARGS)
    ok = authorize(seal_t, _ARGS_TAMPERED, _RUN_A, "proof-tamper")
    results["arg_tampered"] = "BLOCKED" if not ok else "ALLOWED(!)"

    passed = (
        results["genuine"] == "ALLOWED"
        and all(results[g] == "BLOCKED" for g in
                ("forged", "cross_context", "replayed", "arg_tampered"))
    )
    return results, passed
