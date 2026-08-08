"""Protocol conformance for Seal v2. Covers the two bugs the review found plus
the full binding battery and atomic concurrent replay."""
import concurrent.futures as cf
import pytest
from vyrion.protocol import (ApprovalBroker, Approver, WorkflowRef, ExecutionRef,
                             Verifier, ExecutionContext, VerificationError, KeyRing,
                             InMemoryNonceStore, new_keypair, Policy, PolicyRule)

SIGNER = new_keypair("key-1")
POLICY = Policy(id="pay", version="7",
                rules=[PolicyRule(action="payments.transfer", environment="production",
                                  approver_groups=("payments-ops",), maximum_amount=100000)],
                group_membership={"cfo@corp": ["payments-ops"]})


def broker():
    return ApprovalBroker(SIGNER, policy=POLICY)


def ctx(**over):
    d = dict(action_id="payments.transfer", action_fingerprint="fp1",
             args={"recipient": "acct-A", "amount": 1000, "currency": "USD"},
             run_id="run-1", checkpoint_id="cp-1", approval_point_id="pay-approve",
             tenant="default", environment="production", audience="payments")
    d.update(over)
    return ExecutionContext(**d)


def issue(**over):
    d = dict(approver=Approver(subject="cfo@corp", assurance_level="mfa"),
             decision="approve", action_id="payments.transfer", action_fingerprint="fp1",
             args={"recipient": "acct-A", "amount": 1000, "currency": "USD"},
             workflow=WorkflowRef(system="langgraph", run_id="run-1", checkpoint_id="cp-1"),
             execution=ExecutionRef(tenant="default", environment="production", audience="payments"),
             approval_point_id="pay-approve", amount=1000)
    d.update(over)
    return broker().issue(**d)


def verifier():
    ring = KeyRing(); ring.trust(SIGNER.verifier())
    return Verifier(ring, InMemoryNonceStore(), policy=POLICY), ring


def test_genuine_allowed():
    v, _ = verifier()
    v.verify_and_consume(issue(), ctx())  # no raise


def test_signed_deny_blocked():
    v, _ = verifier()
    with pytest.raises(VerificationError):
        v.verify_and_consume(issue(decision="deny"), ctx())


def test_cross_checkpoint_reuse_blocked():
    v, _ = verifier()
    with pytest.raises(VerificationError):
        v.verify_and_consume(issue(), ctx(checkpoint_id="cp-OTHER"))


@pytest.mark.parametrize("over", [
    {"args": {"recipient": "acct-A", "amount": 999999, "currency": "USD"}},
    {"args": {"recipient": "EVIL", "amount": 1000, "currency": "USD"}},
    {"action_id": "db.delete"}, {"run_id": "run-2"}, {"tenant": "other"},
    {"environment": "staging"}, {"audience": "other"},
])
def test_binding_mismatch_blocked(over):
    v, _ = verifier()
    with pytest.raises(VerificationError):
        v.verify_and_consume(issue(), ctx(**over))


def test_expired_blocked():
    v, _ = verifier()
    with pytest.raises(VerificationError):
        v.verify_and_consume(issue(ttl_seconds=-1), ctx())


def test_sequential_replay_blocked():
    v, _ = verifier(); ev = issue()
    v.verify_and_consume(ev, ctx())
    with pytest.raises(VerificationError):
        v.verify_and_consume(ev, ctx())


def test_revoked_key_blocked():
    v, ring = verifier(); ev = issue(); ring.revoke("key-1")
    with pytest.raises(VerificationError):
        v.verify_and_consume(ev, ctx())


def test_unauthorized_approver_refused_at_issuance():
    with pytest.raises(PermissionError):
        issue(approver=Approver(subject="intern@corp", assurance_level="mfa"))


def test_concurrent_replay_single_execution():
    v, _ = verifier(); ev = issue()
    def attempt(i):
        try:
            v.verify_and_consume(ev, ctx(execution_id=f"w{i}")); return 1
        except VerificationError:
            return 0
    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        assert sum(ex.map(attempt, range(100))) == 1
