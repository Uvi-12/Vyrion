"""The approval broker: authenticates the human, evaluates policy, issues a Seal.

Only the broker holds the signer. It refuses to issue unless the policy authorizes
the approver for the action, and it stamps the arguments commitment, key id, and
policy hash into the signed event.
"""

from __future__ import annotations

import time
from typing import Optional

from .canonical import arguments_commitment
from .event import (ActionRef, ApprovalEvent, Approver, ExecutionRef, PolicyRef,
                    WorkflowRef)
from .keys import Ed25519Signer
from .policy import Policy


class ApprovalBroker:
    def __init__(self, signer: Ed25519Signer, policy: Optional[Policy] = None,
                 issuer_id: str = "vyrion-broker", tenant: str = "default"):
        self.signer = signer
        self.policy = policy
        self.issuer_id = issuer_id
        self.tenant = tenant

    def issue(self, *, approver: Approver, decision: str,
              action_id: str, action_fingerprint: str, args: dict,
              workflow: WorkflowRef, execution: ExecutionRef,
              approval_point_id: str, approval_point_fingerprint: str = "",
              requester_subject: str = "", amount: Optional[float] = None,
              approvers: int = 1, ttl_seconds: int = 300,
              now: Optional[float] = None) -> ApprovalEvent:
        now = now if now is not None else time.time()
        if self.policy is not None and decision == "approve":
            d = self.policy.authorize(
                action=action_id, environment=execution.environment,
                approver_subject=approver.subject, requester_subject=requester_subject,
                amount=amount, assurance=approver.assurance_level, approvers=approvers)
            if not d.allowed:
                raise PermissionError(f"policy refused issuance: {d.reason}")
        policy_ref = PolicyRef(id=self.policy.id, version=self.policy.version,
                               hash=self.policy.hash()) if self.policy else PolicyRef()
        event = ApprovalEvent.new(
            issuer_id=self.issuer_id, issuer_tenant=self.tenant,
            key_id=self.signer.key_id, decision=decision, approver=approver,
            approval_point_id=approval_point_id,
            approval_point_fingerprint=approval_point_fingerprint,
            action=ActionRef(id=action_id,
                             implementation_fingerprint=action_fingerprint,
                             arguments_commitment=arguments_commitment(args)),
            workflow=workflow, execution=execution, policy=policy_ref,
            ttl_seconds=ttl_seconds, now=now)
        event.signature = self.signer.sign(event.signing_payload())
        return event
