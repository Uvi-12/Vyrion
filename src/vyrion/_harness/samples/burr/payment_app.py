"""Sample Apache Burr application with a human approval interrupt and persistence."""
from burr.core import ApplicationBuilder, State, action


@action(reads=["amount"], writes=["approval"])
def request_approval(state: State) -> State:
    # pauses for human input; approval persisted to the Burr state store
    return state.update(approval="pending")


@action(reads=["approval"], writes=["executed"])
def transfer_funds(state: State) -> State:
    # protected action
    return state.update(executed=state["approval"] == "approve")


def build():
    return (ApplicationBuilder()
            .with_actions(request_approval, transfer_funds)
            .with_transitions(("request_approval", "transfer_funds")))
