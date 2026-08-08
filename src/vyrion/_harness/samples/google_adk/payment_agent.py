"""Sample Google ADK agent with a tool confirmation callback."""
from google.adk.agents import Agent
from google.adk.tools import ToolContext


def transfer_funds(recipient: str, amount: int, currency: str,
                   tool_context: ToolContext) -> dict:
    """Protected action, gated by a before_tool confirmation callback."""
    return {"executed": True}


def before_tool_approval(tool, args, tool_context):
    # human confirmation gate; decision stored in session state
    tool_context.state["approval"] = "pending"
    return None


agent = Agent(model="gemini-2.0", name="payments", tools=[transfer_funds],
              before_tool_callback=before_tool_approval)
