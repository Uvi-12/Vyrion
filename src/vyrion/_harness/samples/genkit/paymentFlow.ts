// Sample Genkit flow with a human-in-the-loop interrupt before a tool.
import { genkit, z } from 'genkit';

const ai = genkit({});

export const transferFunds = ai.defineTool(
  {
    name: 'transferFunds',
    description: 'Protected action: execute a wire transfer',
    inputSchema: z.object({ recipient: z.string(), amount: z.number(), currency: z.string() }),
  },
  async (input) => {
    return { executed: true };
  }
);

export const paymentFlow = ai.defineFlow(
  { name: 'paymentFlow' },
  async (input, { interrupt, resumed }) => {
    // human approval interrupt; decision persisted in flow state and resumed
    if (!resumed) {
      interrupt({ question: 'Approve payment?', amount: input.amount });
    }
    const approval = resumed?.approval;
    if (approval === 'approve') {
      return transferFunds(input);
    }
    return { executed: false };
  }
);
