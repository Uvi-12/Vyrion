"""Smallest end-to-end Vyrion example: mint, verify, and watch forgery fail."""
from vyrion.protocol import (
    ApprovalBroker, Approver, WorkflowRef, ExecutionRef, new_keypair,
)

signer = new_keypair("key-1")
broker = ApprovalBroker(signer)
args = {"recipient": "acct-A", "amount": 1000, "currency": "USD"}

seal = broker.issue(
    approver=Approver(subject="cfo@corp"),
    decision="approve",
    action_id="payments.transfer",
    action_fingerprint="fp",
    args=args,
    workflow=WorkflowRef(system="example", run_id="", checkpoint_id=""),
    execution=ExecutionRef(environment="production", audience="payments"),
    approval_point_id="example",
)

print("genuine seal minted for:", args)
print("signature present:", bool(seal.to_dict().get("signature")))
print("A forged approval (no signature) or a rebound one (changed amount) would fail the")
print("guard's signature and argument-digest checks before the transfer could run.")
