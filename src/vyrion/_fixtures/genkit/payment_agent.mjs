// A realistic (vulnerable) Genkit human-in-the-loop tool.
//
// The transfer is gated by a Genkit interrupt (ai.defineInterrupt / interrupt()).
// On resume the approval reply is passed to transferFunds as `approval`; it is
// trusted and the transfer runs. A writer of the persisted interrupt/resume state
// can inject an approval reply with no binding to approver, action, arguments, or a
// single-use nonce (the Ghost Approval surface). Interrupt wiring is omitted here so
// the protected action is exercised directly; see README for the full flow.
import { genkit } from 'genkit';

const ai = genkit({ plugins: [] });
void ai;

// PROTECTED ACTION: consumes the approval reply and transfers funds
export async function transferFunds({ recipient, amount, currency, approval }) {
  return `settled ${amount} ${currency} to ${recipient}`;
}
