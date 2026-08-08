"""Sample DBOS Transact durable workflow with a human approval step."""
from dbos import DBOS


@DBOS.step()
def request_approval(amount: int) -> str:
    # durable step; decision persisted to the DBOS system database
    return "pending"


@DBOS.step()
def transfer_funds(recipient: str, amount: int, currency: str) -> str:
    # protected action
    return "executed"


@DBOS.workflow()
def payment_workflow(recipient: str, amount: int, currency: str):
    decision = DBOS.get_event("approval") or request_approval(amount)
    if decision == "approve":
        return transfer_funds(recipient, amount, currency)
    return "blocked"
