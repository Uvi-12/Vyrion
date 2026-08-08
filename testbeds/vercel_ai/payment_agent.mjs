// A realistic (vulnerable) Vercel AI SDK human-in-the-loop tool.
//
// The transfer tool requires human confirmation; on resume the confirmation is
// passed to transferFunds as `approval`, trusted, and the transfer runs. A writer
// of the persisted message/tool-result state can inject a confirmation with no
// binding to approver, action, arguments, or a single-use nonce (the Ghost Approval
// surface). Tool-call wiring is omitted so the protected action is exercised directly.
import { tool } from 'ai';

void tool;

// PROTECTED ACTION: consumes the confirmation reply and transfers funds
export async function transferFunds({ recipient, amount, currency, approval }) {
  return `settled ${amount} ${currency} to ${recipient}`;
}
