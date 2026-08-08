# What a Ghost Approval is

A **Ghost Approval** is an action that runs as if a human approved it, when no human did.

The underlying flaw is **Approval-Provenance Failure**: a system requires a human to
approve a risky action, records that approval as state, and later trusts that state
without checking where it came from. Provenance is the missing question. The system asks
"is this approved?" but never asks "who approved it, for exactly which action, and can
they prove it?"

## Why it happens

Modern agents, workflow engines, and CI/CD pipelines pause at an approval gate and
**persist** their state so they can resume later. The approval decision ends up as a
field in that persisted state, for example `approved: true`, sitting next to the action
arguments like `amount` and `recipient`. On resume, the code reads those fields back and
executes. Nothing re-checks that the approval came from a person, or that the arguments
are still the ones the person saw.

## The five ways it breaks

Once an approval is just mutable state, an attacker who can write that state can:

- **Forge** — write `approved: true` for an action no human ever saw.
- **Rebind** — keep a genuine approval but change the arguments, so the reviewer approved
  a small transfer and a large one executes.
- **Replay** — reuse one genuine approval to run the action twice.
- **Suppress** — remove the approval requirement, so nothing records that one was needed.
- **Launder** — attach an approval issued for one action onto a different action.

In every case the audit log still names a real approver. That is what makes it a *ghost*:
the record looks clean.

## What is required to exploit it

Not a stolen credential, not a prompt injection, not code execution. Only **write access
to the state store the workflow already trusts**. Loggers, exporters, backup jobs, queue
consumers, and over-permissioned database roles often have exactly that, while having no
business making an approval decision.

## The fix, in one line

Bind the approval to the specific action, arguments, run, approver, and a one-time nonce,
sign it, and verify that binding at the moment of execution. That is the
[Vyrion Seal](the-seal.md).
