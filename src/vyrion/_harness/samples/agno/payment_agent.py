"""Sample Agno agent with a requires_confirmation tool."""
from agno.agent import Agent
from agno.tools import tool


@tool(requires_confirmation=True)
def transfer_funds(recipient: str, amount: int, currency: str) -> str:
    """Protected action requiring user confirmation."""
    return "executed"


agent = Agent(name="payments", tools=[transfer_funds])
