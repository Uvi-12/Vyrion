"""Vyrion approval broker (installed by `vyrion apply`).

Holds the private signing key (on disk, outside the mutable workflow state) and
mints a signed Seal at the moment of human approval, bound to the trusted run id
the caller passes in. An attacker who can only write the persisted checkpoint
cannot mint a Seal because the key is not in the checkpoint.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from vyrion.protocol import (ApprovalBroker, Approver, WorkflowRef, ExecutionRef,
                             Ed25519Signer)

_STATE = {"broker": None, "manifest": None, "root": None}


def _find_vyrion_dir(start):
    p = Path(start).resolve()
    for cand in [p] + list(p.parents):
        if (cand / ".vyrion" / "manifest.json").exists():
            return cand / ".vyrion"
    return None


def _load():
    if _STATE["broker"] is not None:
        return _STATE["broker"], _STATE["manifest"]
    vdir = _find_vyrion_dir(_STATE["root"] or os.path.dirname(__file__) or ".") \
        or _find_vyrion_dir(os.getcwd())
    manifest = json.loads((vdir / "manifest.json").read_text())
    signer = Ed25519Signer.from_private_pem("key-1", (vdir / "signing-key.pem").read_bytes())
    _STATE["broker"] = ApprovalBroker(signer)
    _STATE["manifest"] = manifest
    return _STATE["broker"], manifest


def configure(root=None):
    if root is not None:
        _STATE["root"] = root
        _STATE["broker"] = None


def mint(*, run_id, args, decision="approve", approver="human"):
    """Return a signed Seal (JSON string) for this approval, bound to run_id."""
    broker, m = _load()
    event = broker.issue(
        approver=Approver(subject=approver), decision=decision,
        action_id=m.get("action_id", ""), action_fingerprint=m.get("action_fingerprint", ""),
        args=args,
        workflow=WorkflowRef(system=m.get("framework", ""), run_id=run_id or "", checkpoint_id=""),
        execution=ExecutionRef(environment=m.get("environment", "production"),
                               audience=m.get("audience", "default")),
        approval_point_id=m.get("approval_point", ""))
    return json.dumps(event.to_dict())
