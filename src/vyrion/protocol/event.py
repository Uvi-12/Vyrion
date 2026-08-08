"""The Seal v2 approval event.

A signed, execution-bound artifact. Every field the verifier checks is part of
the signed payload, so tampering with any of them invalidates the signature. The
signing payload is the RFC 8785 canonicalization of the event minus the signature.
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

from .canonical import canonicalize, sha256_hex


@dataclass
class Approver:
    subject: str                       # immutable IdP subject
    idp: str = "corporate-idp"
    display_name: str = ""
    authenticated_at: float = 0.0
    methods: tuple = ("password",)
    assurance_level: str = "mfa"

    def to_dict(self) -> dict:
        return {"subject": self.subject, "idp": self.idp,
                "display_name": self.display_name,
                "authenticated_at": self.authenticated_at,
                "methods": list(self.methods), "assurance_level": self.assurance_level}


@dataclass
class ActionRef:
    id: str
    implementation_fingerprint: str = ""
    arguments_commitment: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WorkflowRef:
    system: str
    application_id: str = ""
    run_id: str = ""
    thread_id: str = ""
    checkpoint_id: str = ""
    task_id: str = ""
    tool_call_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExecutionRef:
    tenant: str = "default"
    environment: str = "production"
    audience: str = "default"
    resource: str = ""
    idempotency_key: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PolicyRef:
    id: str = "default"
    version: str = "1"
    hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ApprovalEvent:
    schema_version: str
    event_id: str
    issuer_id: str
    issuer_tenant: str
    key_id: str
    decision: str
    approver: Approver
    approval_point_id: str
    approval_point_fingerprint: str
    action: ActionRef
    workflow: WorkflowRef
    execution: ExecutionRef
    policy: PolicyRef
    issued_at: float
    not_before: float
    expires_at: float
    nonce: str
    parent_event_hash: str = ""
    quorum_id: str = ""
    signature: str = ""

    SCHEMA = "vyrion.approval.v2"

    @staticmethod
    def new(**kw) -> "ApprovalEvent":
        now = kw.pop("now", time.time())
        ttl = kw.pop("ttl_seconds", 300)
        return ApprovalEvent(
            schema_version=ApprovalEvent.SCHEMA,
            event_id=kw.pop("event_id", uuid.uuid4().hex),
            issuer_id=kw.pop("issuer_id", "vyrion-broker"),
            issuer_tenant=kw.pop("issuer_tenant", "default"),
            key_id=kw.pop("key_id", ""),
            decision=kw.pop("decision", "approve"),
            approver=kw.pop("approver"),
            approval_point_id=kw.pop("approval_point_id"),
            approval_point_fingerprint=kw.pop("approval_point_fingerprint", ""),
            action=kw.pop("action"),
            workflow=kw.pop("workflow"),
            execution=kw.pop("execution", ExecutionRef()),
            policy=kw.pop("policy", PolicyRef()),
            issued_at=now,
            not_before=kw.pop("not_before", now),
            expires_at=kw.pop("expires_at", now + ttl),
            nonce=kw.pop("nonce", secrets.token_hex(16)),
            parent_event_hash=kw.pop("parent_event_hash", ""),
            quorum_id=kw.pop("quorum_id", ""),
        )

    def signing_dict(self) -> dict:
        """Everything except the signature, in a stable nested dict."""
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "issuer_id": self.issuer_id,
            "issuer_tenant": self.issuer_tenant,
            "key_id": self.key_id,
            "decision": self.decision,
            "approver": self.approver.to_dict(),
            "approval_point_id": self.approval_point_id,
            "approval_point_fingerprint": self.approval_point_fingerprint,
            "action": self.action.to_dict(),
            "workflow": self.workflow.to_dict(),
            "execution": self.execution.to_dict(),
            "policy": self.policy.to_dict(),
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "parent_event_hash": self.parent_event_hash,
            "quorum_id": self.quorum_id,
        }

    def signing_payload(self) -> bytes:
        return canonicalize(self.signing_dict())

    def event_hash(self) -> str:
        return "sha256:" + sha256_hex(self.signing_payload())

    def to_dict(self) -> dict:
        d = self.signing_dict()
        d["signature"] = self.signature
        return d

    @staticmethod
    def from_dict(d: dict) -> "ApprovalEvent":
        ev = ApprovalEvent(
            schema_version=d["schema_version"], event_id=d["event_id"],
            issuer_id=d["issuer_id"], issuer_tenant=d["issuer_tenant"],
            key_id=d["key_id"], decision=d["decision"],
            approver=Approver(**{**d["approver"], "methods": tuple(d["approver"]["methods"])}),
            approval_point_id=d["approval_point_id"],
            approval_point_fingerprint=d["approval_point_fingerprint"],
            action=ActionRef(**d["action"]), workflow=WorkflowRef(**d["workflow"]),
            execution=ExecutionRef(**d["execution"]), policy=PolicyRef(**d["policy"]),
            issued_at=d["issued_at"], not_before=d["not_before"], expires_at=d["expires_at"],
            nonce=d["nonce"], parent_event_hash=d.get("parent_event_hash", ""),
            quorum_id=d.get("quorum_id", ""), signature=d.get("signature", ""))
        return ev
