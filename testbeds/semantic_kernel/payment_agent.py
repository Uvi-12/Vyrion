"""A realistic (vulnerable) Semantic Kernel Process step gated by a human approval.

In the SK Process framework, human input arrives as an external event routed to a
step, and KernelProcessState is serialized ("enabling replay"). A writer of that
checkpointed state can inject the approval event with no binding to approver, action,
arguments, or a single-use nonce, and the step runs on replay (the Ghost Approval
surface). (SK's filter-based HITL is in-process and is a resistant control.)
"""
from semantic_kernel.processes.kernel_process.kernel_process_step import KernelProcessStep
from semantic_kernel.functions import kernel_function


class PaymentStep(KernelProcessStep):
    @kernel_function
    async def transfer_funds(self, recipient: str, amount: int, currency: str, approval: str) -> str:
        # PROTECTED ACTION
        return f"settled {amount} {currency} to {recipient}"
