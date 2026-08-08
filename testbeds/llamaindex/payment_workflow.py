"""A realistic (vulnerable) LlamaIndex workflow.

An InputRequiredEvent pauses for human approval; the decision is carried in the
workflow Context store, which is serialized between pause and resume. transfer_funds
is the protected step. Any writer of the serialized context can set the approval.
"""
from llama_index.core.workflow import (Workflow, step, Context, StartEvent, StopEvent,
                                        InputRequiredEvent, HumanResponseEvent)


class PaymentWorkflow(Workflow):
    @step
    async def request_approval(self, ctx: Context, ev: StartEvent) -> InputRequiredEvent:
        await ctx.store.set("recipient", getattr(ev, "recipient", "acct-A"))
        await ctx.store.set("amount", getattr(ev, "amount", 1000))
        await ctx.store.set("currency", getattr(ev, "currency", "USD"))
        await ctx.store.set("action", "transfer_funds")
        await ctx.store.set("approval", "pending")
        return InputRequiredEvent(prefix="Approve transfer?")

    @step
    async def transfer_funds(self, ctx: Context, ev: HumanResponseEvent) -> StopEvent:
        # PROTECTED STEP
        approved = ev.response == "approve"
        return StopEvent(result={"executed": approved})
