# Vyrion documentation

Vyrion finds and fixes **Ghost Approvals**: cases where a human approval can be forged
because it is stored as ordinary state and trusted on resume without checking where it
came from.

Start here:

- **[What a Ghost Approval is](concepts/approval-provenance-failure.md)** — the vulnerability class, in plain language.
- **[Threat model](concepts/threat-model.md)** — who the attacker is and what they can do.
- **[How the Seal works](concepts/the-seal.md)** — the fix, and what it binds.
- **[The cross-language Seal](concepts/cross-language-seal.md)** — one guarantee across Python and Node.
- **[How verification works](verification.md)** — what "certified" means and how it is proven.
- **[Support matrix](support-matrix.md)** — the fifteen certified frameworks.
- **[Coordinated disclosure record](research/disclosures.md)** — what the vendors said.

Guides for using the tool are in [guide/](guide/).
