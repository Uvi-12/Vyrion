"""Authorization policy: who may approve what, under which conditions.

Beyond signature validity, the verifier asks the policy whether this approver is
allowed to authorize this action in this environment: role/group membership,
environment and action scope, amount ceilings, self-approval prevention, and
required approver count. The policy document is versioned and hashed so a
rollback to an older policy is detectable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .canonical import canonicalize, sha256_hex


@dataclass
class PolicyRule:
    action: str
    environment: str = "production"
    approver_groups: tuple = ()
    maximum_amount: Optional[float] = None
    prevent_self_approval: bool = True
    minimum_approvers: int = 1
    require_assurance: str = ""      # e.g. "phishing-resistant"


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""


@dataclass
class Policy:
    id: str
    version: str
    rules: list = field(default_factory=list)
    group_membership: dict = field(default_factory=dict)  # subject -> [groups]

    def hash(self) -> str:
        body = {"id": self.id, "version": self.version,
                "rules": [vars(r) for r in self.rules]}
        return "sha256:" + sha256_hex(canonicalize(body))

    def rule_for(self, action: str, environment: str) -> Optional[PolicyRule]:
        for r in self.rules:
            if r.action == action and r.environment == environment:
                return r
        return None

    def authorize(self, *, action: str, environment: str, approver_subject: str,
                  requester_subject: str = "", amount: Optional[float] = None,
                  assurance: str = "", approvers: int = 1) -> PolicyDecision:
        rule = self.rule_for(action, environment)
        if rule is None:
            return PolicyDecision(False, f"no policy rule for {action} in {environment}")
        groups = set(self.group_membership.get(approver_subject, []))
        if rule.approver_groups and not (groups & set(rule.approver_groups)):
            return PolicyDecision(False, "approver not in an authorized group")
        if rule.prevent_self_approval and requester_subject and \
                approver_subject == requester_subject:
            return PolicyDecision(False, "self-approval is not permitted")
        if rule.maximum_amount is not None and amount is not None and \
                amount > rule.maximum_amount:
            return PolicyDecision(False, "amount exceeds policy maximum")
        if rule.require_assurance and assurance != rule.require_assurance:
            return PolicyDecision(False, "assurance level below policy requirement")
        if approvers < rule.minimum_approvers:
            return PolicyDecision(False, "insufficient approvers for quorum")
        return PolicyDecision(True, "authorized")
