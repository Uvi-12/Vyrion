"""A realistic (vulnerable) Strands tool gated by a human interrupt.

The tool pauses via tool_context.interrupt(); the response lives in the agent's
interrupt state and is trusted on resume. A writer of that persisted state can
inject an approval response with no binding to approver, action, arguments, or a
single-use nonce, and the tool runs on resume (the Ghost Approval surface).
"""
from strands import tool, ToolContext


@tool(context=True)
def transfer_funds(recipient: str, amount: int, currency: str, tool_context: ToolContext) -> str:
    response = tool_context.interrupt("approve_transfer", reason="approve this payment?")
    # PROTECTED ACTION
    return f"settled {amount} {currency} to {recipient}"
