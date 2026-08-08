"""Sample Haystack pipeline with a breakpoint before a side-effect component."""
from haystack import Pipeline
from haystack.dataclasses.breakpoints import Breakpoint


def build_pipeline():
    pipe = Pipeline()
    # human review breakpoint; snapshot persisted and edited before resume
    approval_breakpoint = Breakpoint(component_name="transfer_funds", visit_count=0)
    return pipe, approval_breakpoint


def transfer_funds(recipient: str, amount: int, currency: str) -> dict:
    """Protected component with an external side effect."""
    return {"executed": True}
