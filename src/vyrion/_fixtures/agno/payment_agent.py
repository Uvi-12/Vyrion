"""A realistic (vulnerable) Agno tool gated by requires_confirmation.

Agno serializes the tool confirmation (confirmed / confirmation_note) into the run /
session state. A writer of that state can set confirmed=True with no binding to
approver, action, arguments, or a single-use nonce, and the tool runs on resume
(the Ghost Approval surface).
"""
from agno.tools import tool


@tool(requires_confirmation=True)
def transfer_funds(recipient: str, amount: int, currency: str, approval: str) -> str:
    # PROTECTED ACTION
    return f"settled {amount} {currency} to {recipient}"
