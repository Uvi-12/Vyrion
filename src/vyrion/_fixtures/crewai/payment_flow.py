"""A realistic (vulnerable) CrewAI Flow with a human-approval gate.

The flow pauses at a @human_feedback point; on resume the persisted feedback is
trusted and the transfer runs. A writer of the flow_states / pending_feedback
store can inject the approval with no binding to approver, action, arguments, or
a single-use nonce (the Ghost Approval surface).
"""
from pydantic import BaseModel
from crewai.flow.flow import Flow, start, listen
from crewai.flow.dsl._human_feedback import human_feedback


class PaymentState(BaseModel):
    recipient: str = "acct-A"
    amount: int = 1000
    currency: str = "USD"
    settled: bool = False


class PaymentFlow(Flow[PaymentState]):
    @start()
    def begin(self):
        return "begin"

    @human_feedback(message="Approve this payment?", emit=None)
    @listen(begin)
    def request_approval(self):
        return f"Approve payment of {self.state.amount} {self.state.currency} to {self.state.recipient}?"

    @listen(request_approval)
    def transfer_funds(self, feedback):
        # PROTECTED ACTION
        self.state.settled = True
        return f"settled {self.state.amount} {self.state.currency} to {self.state.recipient}"
