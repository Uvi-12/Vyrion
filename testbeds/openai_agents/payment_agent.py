"""A realistic (vulnerable) OpenAI Agents SDK agent with a human-approval tool.

The transfer tool is declared needs_approval=True. On a resumed run the approval
is read back from RunState (RunState.to_json / from_json) with no integrity check,
so a writer of the serialized state can set approved=true and the tool executes
with no binding to approver, action, arguments, or a single-use nonce.
"""
from agents import Agent, function_tool
from agents.tool_context import ToolContext


@function_tool(needs_approval=True)
def transfer_funds(ctx: ToolContext, recipient: str, amount: int, currency: str) -> str:
    # PROTECTED ACTION
    return f"settled {amount} {currency} to {recipient}"


payment_agent = Agent(name="payments", tools=[transfer_funds])
