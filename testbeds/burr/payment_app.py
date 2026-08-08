"""A realistic (vulnerable) Burr payment application.

The human's approval decision arrives as a Burr input to process_approval; the
decision is written into the persisted State and read back by transfer_funds.
Any writer of the persisted State can set approval and cause the transfer, with
no binding to approver, action, arguments, or the application run.
"""
from burr.core import ApplicationBuilder, State, action


@action(reads=["recipient", "amount", "currency"], writes=["approval"])
def process_approval(state: State, decision: str) -> State:
    # the trusted approver's decision arrives as a run-time input
    return state.update(approval=decision)


@action(reads=["approval", "recipient", "amount", "currency"], writes=["executed"])
def transfer_funds(state: State) -> State:
    # PROTECTED ACTION: moves money based on the persisted approval.
    return state.update(executed=(state["approval"] == "approve"))


def build_app(app_id="burr-demo"):
    return (ApplicationBuilder()
            .with_actions(process_approval=process_approval, transfer_funds=transfer_funds)
            .with_transitions(("process_approval", "transfer_funds"))
            .with_entrypoint("process_approval")
            .with_identifiers(app_id=app_id)
            .with_state(recipient="acct-A", amount=1000, currency="USD",
                        approval="", executed=False)
            .build())
