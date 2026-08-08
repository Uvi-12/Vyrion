# Threat model

## The attacker: a state writer

Vyrion defends against a **state-writer adversary**: a principal that can read and write
the persisted state a workflow uses to pause and resume, but that cannot:

- authenticate as the human reviewer,
- produce the reviewer's genuine approval,
- invoke the protected action directly,
- read the credentials the protected action uses,
- modify the application code,
- compromise the application host, or
- read any signing key used by a hardened approval.

This is deliberately a **weaker** attacker than the usual "assume full compromise." It
models a realistic separation of duties: the component that can write operational state
is often not the component trusted to make a human decision. A logging sidecar, a backup
process, a migration job, or an over-permissioned database role can all be state writers.

## The security property

The property Vyrion protects is **approval provenance**: an action runs only if a genuine
human approval exists for *that exact action, with those exact arguments, in that run*,
and only once.

## Why "the store is the operator's problem" is not enough

Several framework vendors correctly note that the persisted state store is inside the
operator's trust boundary. That is true, and it is also the point. Telling operators to
lock down the store does not give them a way to bind an approval to an action. Even a
perfectly ACL'd store does not stop a *rebind*, where an authorized state-writing
component alters arguments after a genuine approval. Provenance has to be enforced at the
approval itself, not only at the storage layer. See the
[disclosure record](../research/disclosures.md) for how each vendor framed this.

## What Vyrion does not claim

Vyrion does not defend against an attacker who has already stolen the reviewer's identity,
obtained the signing key, or taken over the host. Those are strictly stronger positions
that defeat any approval scheme. Vyrion closes the specific, common gap where writing
trusted state is enough to forge a human decision.
