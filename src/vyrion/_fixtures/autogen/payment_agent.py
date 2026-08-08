"""A realistic (vulnerable) AutoGen agent whose transfer tool trusts an approval.

AutoGen serializes agent/team state via save_state / load_state as plain JSON with
no integrity check. A writer of that serialized state can inject an approval (your
MSRC finding: appending to message_buffer / setting next_speaker_index) so the tool
runs on resume with no binding to approver, action, arguments, or a single-use nonce.
"""
from autogen_agentchat.agents import AssistantAgent  # noqa: F401
from autogen_core.tools import FunctionTool


def transfer_funds(recipient: str, amount: int, currency: str, approval: str) -> str:
    # PROTECTED ACTION
    return f"settled {amount} {currency} to {recipient}"


transfer_tool = FunctionTool(transfer_funds, description="transfer funds after human approval")
