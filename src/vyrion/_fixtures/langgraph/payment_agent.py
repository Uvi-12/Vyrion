"""A realistic (vulnerable) LangGraph payment agent.

An interrupt pauses for human approval; the decision is persisted in the graph
state via the checkpointer and read back on resume. transfer_funds is the
protected action. As written, any writer of the persisted checkpoint can set the
approval and cause the transfer, with no binding to approver, action, arguments,
run, or checkpoint.
"""
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
    # PROTECTED ACTION: moves real money based on the persisted approval.
    if state.get("approval") == "approve":
        return {"executed": True}
    return {"executed": False}


def build_graph(checkpointer):
    g = StateGraph(State)
    g.add_node("request_payment_approval", request_payment_approval)
    g.add_node("transfer_funds", transfer_funds)
    g.add_edge(START, "request_payment_approval")
    g.add_edge("request_payment_approval", "transfer_funds")
    g.add_edge("transfer_funds", END)
    return g.compile(checkpointer=checkpointer)
