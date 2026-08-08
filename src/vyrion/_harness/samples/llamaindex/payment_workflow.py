"""Sample LlamaIndex workflow with a human response approval step."""
from llama_index.core.workflow import (Workflow, step, Context, StartEvent, StopEvent,
                                        InputRequiredEvent, HumanResponseEvent)


class PaymentWorkflow(Workflow):
    @step
    async def request_approval(self, ctx: Context, ev: StartEvent) -> InputRequiredEvent:
        await ctx.store.set("action", "transfer_funds")
        await ctx.store.set("approval", "pending")
        return InputRequiredEvent(prefix="Approve transfer?")

    @step
    async def transfer_funds(self, ctx: Context, ev: HumanResponseEvent) -> StopEvent:
        approved = ev.response == "approve"
        return StopEvent(result={"executed": approved})
