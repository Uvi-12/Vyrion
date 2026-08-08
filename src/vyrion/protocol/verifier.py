"""The runtime verifier: fail-closed, execution-bound.

Given an event and the ACTUAL execution context (real action id, real arguments
recomputed at the call site, real run and checkpoint, real environment), the
verifier rejects unless every bound field matches, the decision is approve, the
signature is valid under a trusted non-revoked key, the policy hash matches, the
event is within its validity window, and the nonce consumes atomically. There is
no path that returns success by default.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .canonical import arguments_commitment
from .event import ApprovalEvent
from .keys import KeyRing
from .nonce import NonceStore
from .policy import Policy


class VerificationError(Exception):
    pass


@dataclass
class ExecutionContext:
    """The real values, resolved at the execution site, not from stored state."""
    action_id: str
    action_fingerprint: str
    args: dict
    run_id: str
    checkpoint_id: str
    approval_point_id: str
    tenant: str = "default"
    environment: str = "production"
    audience: str = "default"
    execution_id: str = "exec-1"


class Verifier:
    def __init__(self, keyring: KeyRing, nonce_store: NonceStore,
                 policy: Optional[Policy] = None):
        self.keyring = keyring
        self.nonce_store = nonce_store
        self.policy = policy

    def verify_and_consume(self, event: ApprovalEvent, ctx: ExecutionContext,
                           *, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()

        if event.schema_version != ApprovalEvent.SCHEMA:
            raise VerificationError("unsupported schema version")
        if event.decision != "approve":
            raise VerificationError(f"decision is not approve: {event.decision!r}")

        verifier = self.keyring.get(event.key_id)
        if verifier is None:
            raise VerificationError("issuer key is untrusted or revoked")
        if not verifier.verify(event.signing_payload(), event.signature):
            raise VerificationError("signature is invalid")

        # timing
        if now < event.not_before:
            raise VerificationError("event is not yet valid (not_before)")
        if now >= event.expires_at:
            raise VerificationError("event has expired")

        # execution binding: every field must match the ACTUAL context
        if event.action.id != ctx.action_id:
            raise VerificationError("action id mismatch")
        if event.action.implementation_fingerprint and \
                event.action.implementation_fingerprint != ctx.action_fingerprint:
            raise VerificationError("action implementation fingerprint mismatch")
        expected_commit = arguments_commitment(ctx.args)
        if event.action.arguments_commitment != expected_commit:
            raise VerificationError("arguments commitment mismatch")
        if event.workflow.run_id != ctx.run_id:
            raise VerificationError("run id mismatch")
        if event.workflow.checkpoint_id != ctx.checkpoint_id:
            raise VerificationError("checkpoint id mismatch")
        if event.approval_point_id != ctx.approval_point_id:
            raise VerificationError("approval point id mismatch")
        if event.execution.tenant != ctx.tenant:
            raise VerificationError("tenant mismatch")
        if event.execution.environment != ctx.environment:
            raise VerificationError("environment mismatch")
        if event.execution.audience != ctx.audience:
            raise VerificationError("audience mismatch")

        # policy currency: reject a rolled-back or altered policy
        if self.policy is not None:
            if event.policy.hash != self.policy.hash():
                raise VerificationError("policy hash mismatch (possible rollback)")
            if event.policy.version != self.policy.version:
                raise VerificationError("policy version mismatch")

        # atomic single-use consumption LAST, so a rejected verify does not burn it
        if not self.nonce_store.consume_once(
                nonce=event.nonce, expires_at=event.expires_at,
                execution_id=ctx.execution_id):
            raise VerificationError("nonce already consumed (replay)")
