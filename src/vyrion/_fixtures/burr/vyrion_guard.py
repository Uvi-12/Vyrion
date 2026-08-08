"""Vyrion execution guard (installed by `vyrion apply`).

This module is imported by the patched application. It self-configures from the
on-disk trust material written next to it (``.vyrion/manifest.json`` and the PEM
public keys under ``.vyrion/public-keys/``), so the protected code only has to
call ``authorize(...)`` right before the guarded action runs.

It holds public verification keys only. It fails closed: any missing seal,
malformed seal, unknown key, or unmet binding returns False and the caller must
block the action.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from vyrion.protocol import (Verifier, ExecutionContext, VerificationError, KeyRing,
                             InMemoryNonceStore, Ed25519Verifier, ApprovalEvent)

_STATE = {"guard": None, "root": None, "context": None}
_LOCK = threading.Lock()


class Blocked(Exception):
    """Raised by a guarded action when approval provenance cannot be verified."""


def set_context(*, seal, args, run_id, checkpoint_id):
    """Host/driver hook: provide the seal + execution context for the next action."""
    _STATE["context"] = {"seal": seal, "args": args, "run_id": run_id,
                         "checkpoint_id": checkpoint_id}


def pending_context():
    return _STATE["context"]


def _find_vyrion_dir(start):
    p = Path(start).resolve()
    for cand in [p] + list(p.parents):
        if (cand / ".vyrion" / "manifest.json").exists():
            return cand / ".vyrion"
    return None


def _load_guard():
    if _STATE["guard"] is not None:
        return _STATE["guard"]
    with _LOCK:
        if _STATE["guard"] is not None:   # double-checked under the lock
            return _STATE["guard"]
        vdir = _find_vyrion_dir(_STATE["root"] or os.path.dirname(__file__) or ".")
        if vdir is None:
            vdir = _find_vyrion_dir(os.getcwd())
        manifest = json.loads((vdir / "manifest.json").read_text())
        ring = KeyRing()
        keydir = vdir / "public-keys"
        if keydir.exists():
            for pem in keydir.glob("*.pem"):
                ring.trust(Ed25519Verifier.from_pem(pem.stem, pem.read_bytes()))
        _STATE["guard"] = _Guard(ring, manifest)
        return _STATE["guard"]


class _Guard:
    def __init__(self, keyring, manifest, nonce_store=None):
        self.verifier = Verifier(keyring, nonce_store or InMemoryNonceStore())
        self.action_id = manifest.get("action_id", "")
        self.action_fingerprint = manifest.get("action_fingerprint", "")
        self.approval_point_id = manifest.get("approval_point", "")
        self.environment = manifest.get("environment", "production")
        self.audience = manifest.get("audience", "default")
        self.tenant = manifest.get("tenant", "default")

    def authorize(self, *, seal, args, run_id, checkpoint_id, execution_id="exec"):
        if not seal:
            return False
        try:
            if isinstance(seal, str):
                seal = json.loads(seal)
            event = ApprovalEvent.from_dict(seal)
        except Exception:
            return False   # malformed seal fails closed
        try:
            ctx = ExecutionContext(
                action_id=self.action_id, action_fingerprint=self.action_fingerprint,
                args=args, run_id=run_id or "", checkpoint_id=checkpoint_id or "",
                approval_point_id=self.approval_point_id, tenant=self.tenant,
                environment=self.environment, audience=self.audience,
                execution_id=execution_id)
            self.verifier.verify_and_consume(event, ctx)
            return True
        except VerificationError:
            return False


def configure(root=None, guard=None):
    """Test/host hook: pin the project root or inject a preconfigured guard."""
    if root is not None:
        _STATE["root"] = root
        _STATE["guard"] = None
    if guard is not None:
        _STATE["guard"] = guard


def authorize(*, seal, args, run_id, checkpoint_id, execution_id="exec"):
    """Return True only if a valid Seal authorizes THIS exact invocation."""
    return _load_guard().authorize(seal=seal, args=args, run_id=run_id,
                                   checkpoint_id=checkpoint_id, execution_id=execution_id)
