"""A realistic (vulnerable) Airflow DAG with a human-approval gate.

Airflow's native HITL (ApprovalOperator / HITLOperator) records the human response in
the metadata DB; a downstream task reads it and executes. A writer of the metadata DB
(Variable / XCom / HITL response) can inject an approval with no binding to approver,
action, arguments, or a single-use nonce, and the task runs (the Ghost Approval surface).
"""
from airflow.providers.standard.operators.hitl import ApprovalOperator  # noqa: F401


def transfer_funds(recipient, amount, currency, approval):
    # PROTECTED ACTION (downstream task consuming the HITL response)
    return f"settled {amount} {currency} to {recipient}"
