"""Sample LangGraph payment agent with a human approval interrupt."""
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import interrupt, Command


class State(TypedDict, total=False):
    recipient: str
    amount: int
    currency: str
    approval: str
    executed: bool


def request_payment_approval(state: State):
    decision = interrupt({"question": "Approve payment?", "amount": state["amount"]})
    return {"approval": decision}


def transfer_funds(state: State):
    if state.get("approval") == "approve":
        # protected action: moves real money
        return {"executed": True}
    return {"executed": False}


def build():
    g = StateGraph(State)
    g.add_node("request_payment_approval", request_payment_approval)
    g.add_node("transfer_funds", transfer_funds)
    g.add_edge(START, "request_payment_approval")
    g.add_edge("request_payment_approval", "transfer_funds")
    g.add_edge("transfer_funds", END)
    return g
