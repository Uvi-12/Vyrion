"""A realistic (vulnerable) DBOS durable payment workflow.

The workflow waits for a human approval via DBOS.recv(); on resume the decision is
read back from the durable notifications table and trusted. Any writer of that
durable state can inject the approval and release the transfer, with no binding to
approver, action, arguments, or the workflow run.
"""
from dbos import DBOS


@DBOS.step()
def transfer_funds(recipient, amount, currency):
    # PROTECTED ACTION
    return f"settled {amount} {currency} to {recipient}"


@DBOS.workflow()
def payment_workflow(recipient, amount, currency):
    decision = DBOS.recv("approval", timeout_seconds=5)
    if decision == "approve":
        return transfer_funds(recipient, amount, currency)
    return "denied"
