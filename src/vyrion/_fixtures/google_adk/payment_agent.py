"""A realistic (vulnerable) Google ADK agent with a require_confirmation tool.

The transfer tool requires human confirmation. The confirmation (ToolConfirmation
with confirmed=True) is delivered as a function response and persisted in the
session (DatabaseSessionService). A writer of that session state can inject a
confirmed=True response with no binding to approver, action, arguments, or a
single-use nonce, and the tool executes on resume (the Ghost Approval surface).
"""
from google.adk.agents import Agent
from google.adk.tools import FunctionTool


def transfer_funds(recipient: str, amount: int, currency: str, tool_context) -> str:
    # PROTECTED ACTION
    return f"settled {amount} {currency} to {recipient}"


transfer_tool = FunctionTool(func=transfer_funds, require_confirmation=True)

payment_agent = Agent(name="payments", model="gemini-2.0-flash", tools=[transfer_tool])
