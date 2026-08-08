"""Sample AutoGen team with a human proxy approval before a tool call."""
from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
from autogen_agentchat.teams import RoundRobinGroupChat


def transfer_funds(recipient: str, amount: int, currency: str) -> str:
    """Protected action: executes a wire transfer."""
    return f"transferred {amount} {currency} to {recipient}"


def build_team():
    approver = UserProxyAgent("human_approver")  # human handoff / approval
    agent = AssistantAgent("payments", tools=[transfer_funds])
    return RoundRobinGroupChat([approver, agent])
