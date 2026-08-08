"""A realistic (vulnerable) Haystack tool gated by a human confirmation.

Haystack's Agent human-in-the-loop produces a ToolExecutionDecision (execute=True,
final_tool_params) that is serialized into the AgentSnapshot. A writer of that
snapshot can inject execute=True with no binding to approver, action, arguments, or
a single-use nonce, and the tool runs on resume (the Ghost Approval surface you
disclosed to deepset).
"""
from haystack.tools import Tool


def transfer_funds(recipient, amount, currency, approval):
    # PROTECTED ACTION
    return f"settled {amount} {currency} to {recipient}"


_params = {"type": "object", "properties": {
    "recipient": {"type": "string"}, "amount": {"type": "integer"},
    "currency": {"type": "string"}, "approval": {"type": "string"}},
    "required": ["recipient", "amount", "currency", "approval"]}

transfer_tool = Tool(name="transfer_funds", description="transfer funds after human approval",
                     parameters=_params, function=transfer_funds)
