# How the Seal works

The **Vyrion Seal** is a signed approval artifact. Where a plain system stores
`approved: true`, Vyrion stores a Seal that answers the provenance question: who approved
what, for which run, and can it be proven, once.

## What a Seal binds

A Seal is a small signed record that binds the approval to:

- the **action** (a stable identifier for the operation),
- the **arguments**, as a canonical digest, so changing them invalidates the Seal,
- the **run and checkpoint** it belongs to, where the framework exposes a trusted id,
- the **approver** identity,
- the **policy** and **audience** it was issued under,
- an **expiry**, and
- a **one-time nonce**, so a Seal cannot be replayed.

The record is canonicalized deterministically and signed with Ed25519.

## How it is checked

Vyrion installs a small **guard** next to the protected action. Before the action runs,
the guard:

1. verifies the signature against the public verification key,
2. recomputes the argument digest from the *current* arguments and checks it matches,
3. checks the action id, run binding, policy, audience, and expiry,
4. consumes the nonce atomically, so a second use is rejected, and
5. fails closed: if anything does not verify, the action does not run.

The guard holds **public verification keys only**. It never holds a signing key, so
installing Vyrion never adds a secret to the protected host.

## How this stops each attack

- **Forge** — no valid signature, so the guard rejects it.
- **Rebind** — the argument digest no longer matches, so the guard rejects it.
- **Replay** — the nonce is already consumed, so the second run is rejected.
- **Suppress** — the guard requires a Seal to proceed and fails closed without one.
- **Launder** — the action id in the Seal does not match the action being run.

## Two binding tiers

Some frameworks expose a **trusted run id** from the runtime at the point of approval
(LangGraph, Apache Burr, DBOS). There the Seal is anchored to that run, which is the
strongest binding. Most frameworks serialize their state as a whole and expose no trusted
run id at the guard; there the Seal binds to action, arguments, and a one-time nonce,
which still defeats forge, rebind, replay, suppress, and launder. Vyrion labels each
framework's tier honestly in the [support matrix](../support-matrix.md); it never invents
an anchor a framework does not provide.
