# Research overview

Vyrion is the practical half of a research finding: **Approval-Provenance Failure**, a
vulnerability class where a human approval can be forged because it is stored as ordinary
state and trusted on resume without a provenance check.

The research characterizes the class across agentic AI frameworks, durable workflow
engines, and CI/CD systems; defines a state-writer adversary; and enumerates five exploit
techniques (forge, rebind, replay, suppress, launder). Vyrion implements the defense the
research proposes: a signed approval artifact that binds the approval to the action and is
verified at execution.

- The vulnerability class: [concepts/approval-provenance-failure.md](../concepts/approval-provenance-failure.md)
- The threat model: [concepts/threat-model.md](../concepts/threat-model.md)
- The defense: [concepts/the-seal.md](../concepts/the-seal.md)
- What vendors said: [disclosures.md](disclosures.md)
