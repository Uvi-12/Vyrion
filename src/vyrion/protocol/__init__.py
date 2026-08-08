"""Vyrion approval protocol v2.

A signed, execution-bound approval event and its verifier. The event binds the
decision, the authenticated approver, the exact action and an arguments
commitment, the workflow run and checkpoint, the approval point, tenant,
environment, audience, policy, timing, and a single-use nonce. Verification is
fail-closed: every bound field must match the actual execution context, the
decision must be approve, and the nonce is consumed atomically.
"""

from .canonical import canonicalize, sha256_hex, arguments_commitment
from .event import ApprovalEvent, Approver, ActionRef, WorkflowRef, ExecutionRef, PolicyRef
from .keys import Ed25519Signer, Ed25519Verifier, KeyRing, new_keypair
from .nonce import NonceStore, InMemoryNonceStore
from .policy import Policy, PolicyRule, PolicyDecision
from .issuer import ApprovalBroker
from .verifier import Verifier, VerificationError, ExecutionContext

__all__ = [
    "canonicalize", "sha256_hex", "arguments_commitment",
    "ApprovalEvent", "Approver", "ActionRef", "WorkflowRef", "ExecutionRef", "PolicyRef",
    "Ed25519Signer", "Ed25519Verifier", "KeyRing", "new_keypair",
    "NonceStore", "InMemoryNonceStore",
    "Policy", "PolicyRule", "PolicyDecision",
    "ApprovalBroker", "Verifier", "VerificationError", "ExecutionContext",
]
