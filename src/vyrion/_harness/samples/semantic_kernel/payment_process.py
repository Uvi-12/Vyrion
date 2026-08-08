"""Sample Semantic Kernel process with an approval step and a guarded function."""
from semantic_kernel.functions import kernel_function


class PaymentPlugin:
    @kernel_function(name="request_approval", description="Ask a human to approve")
    def request_approval(self, amount: int) -> str:
        return "pending"

    @kernel_function(name="transfer_funds", description="Execute the transfer")
    def transfer_funds(self, recipient: str, amount: int, currency: str) -> str:
        # protected action
        return "executed"
