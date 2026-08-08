# The cross-language Seal

Vyrion is written in Python, but two of the supported frameworks (Genkit and Vercel AI)
are JavaScript. Rather than maintain two separate approval schemes, Vyrion uses **one
Seal that both languages agree on**.

## Why it works

A Seal is signed over a deterministic, canonical byte encoding of its fields
(RFC 8785 style canonicalization, then an Ed25519 signature). Because the canonicalization
is deterministic, the same Seal produces the **same canonical bytes** in Python and in
Node, and Node's built-in `crypto` can verify the Ed25519 signature over those bytes
against the public key.

This is checked directly: a Seal minted in Python is canonicalized independently in Node,
the byte strings are compared, and the signature is verified. They match, and it verifies.
The security test for this lives in `tests/security/`.

## What this buys

- One signing and verification scheme, not two that can drift apart.
- The Node guard (`node_guard.mjs`) is small, uses only Node's built-in `crypto`, `fs`,
  and `path`, and has no npm dependencies of its own.
- The same five gates (genuine passes; forge, rebind, replay, and bypass are blocked)
  are enforced identically for Python and JavaScript frameworks.

## Honest scope

Vyrion mints Seals in Python. The Node side verifies. There is no separate JavaScript
signing broker, because the approving authority in the supported flows is the Python
side. The guarantee that matters, "a forged or replayed approval cannot run the action,"
holds identically in both languages.
