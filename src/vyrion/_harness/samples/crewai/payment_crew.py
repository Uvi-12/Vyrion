"""Sample CrewAI flow with a human-input approval task and a transfer tool.

The side effect runs through the ``transfer_funds`` tool the agent calls after
the human-input approval task, which is where a real CrewAI payment flow performs
the mutation. That tool is the protected action Vyrion wires the guard into.
"""
from crewai import Agent, Crew, Task, Process
from crewai.tools import tool


@tool("transfer_funds")
def transfer_funds(recipient: str, amount: int, currency: str) -> dict:
    """Protected action: move real money once the transfer is approved."""
    return {"executed": True, "recipient": recipient, "amount": amount}


approver = Agent(role="Payments Approver", goal="Approve or reject transfers",
                 backstory="Finance operator", tools=[transfer_funds])


def build_crew():
    approval_task = Task(
        description="Review and approve the pending wire transfer",
        agent=approver,
        human_input=True,
    )
    transfer_task = Task(
        description="Execute the approved transfer via the transfer_funds tool",
        agent=approver,
    )
    return Crew(agents=[approver], tasks=[approval_task, transfer_task],
                process=Process.sequential)
