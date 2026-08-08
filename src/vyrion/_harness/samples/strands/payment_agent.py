"""Sample Strands Agents SDK flow with HITL trusted-tools approval."""
from strands import Agent
from strands.tools import tool


@tool
def transfer_funds(recipient: str, amount: int, currency: str) -> str:
    """Protected action. Trust is granted via persisted hitl trusted_tools state."""
    return "executed"


agent = Agent(name="payments", tools=[transfer_funds], enable_trust=True)
