"""Sample OpenAI Agents SDK tool gated with needs_approval."""
from agents import Agent, function_tool


@function_tool(needs_approval=True)
def transfer_funds(recipient: str, amount: int, currency: str) -> str:
    """Protected action: move funds. Requires human approval."""
    return "executed"


agent = Agent(name="payments", tools=[transfer_funds])
