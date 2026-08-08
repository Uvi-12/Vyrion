// Sample Vercel AI SDK tool needing human approval before execution.
import { tool } from 'ai';
import { z } from 'zod';

export const transferFunds = tool({
  description: 'Protected action: execute a wire transfer',
  parameters: z.object({ recipient: z.string(), amount: z.number(), currency: z.string() }),
  // needsApproval gates execution; the approval decision is persisted with the
  // tool call and read back on resume.
  needsApproval: true,
  execute: async ({ recipient, amount, currency }) => {
    return { executed: true };
  },
});
