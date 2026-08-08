<div align="center">

<img src="docs/assets/logo.png" alt="Vyrion" width="180"/>

**Find and fix Ghost Approvals: forged human-approval bypasses in AI agent, workflow, and CI/CD systems.**

[![Version](https://img.shields.io/badge/version-0.2.0--beta-6D4AFF)](https://github.com/Uvi-12/vyrion/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB)](pyproject.toml)
[![Frameworks](https://img.shields.io/badge/frameworks-15%20certified-2ea44f)](docs/support-matrix.md)

</div>

---

## The problem, in one sentence

Many AI agents and workflows pause for a human to approve a risky action, then store that approval as ordinary state and trust it on resume, so anything that can write to that state can forge the approval and the action runs with no human involved.

We call this a **Ghost Approval**. The audit log still shows a human signed off. Nobody did.

The attacker does not need a stolen password, a prompt injection, or code execution. It needs only a write to a store the workflow already trusts, which loggers, exporters, backup jobs, and queue consumers often have.

## See it in 20 seconds

```
pip install vyrion
vyrion demo
```

`vyrion demo` runs a real agent three times:

1. A vulnerable payment tool executes a **forged** one-million-dollar transfer. No human approved it.
2. Vyrion reports the gate as exposed and explains why.
3. The same tool, hardened with a Vyrion Seal, **rejects the forgery** and runs only on a genuine signed approval.

## Install

```
pip install vyrion
```

That is the whole install for the core tool and the demo. To test a specific framework live, add its extra so you only pull what you need:

```
pip install "vyrion[langgraph]"
pip install "vyrion[crewai]"
pip install "vyrion[haystack]"
```

The two Node frameworks (Genkit and Vercel AI) install with npm instead:

```
npm install genkit ai
```

## Use it on your own project

Point Vyrion at a folder. It finds the approval gate, tells you if it is exposed, and can wire in the fix.

```
vyrion run ./my-agent
```

Or drive the three steps yourself:

```
vyrion certify --framework langgraph --live    # prove the fix on a real run
vyrion apply --framework langgraph --project ./my-agent   # wire the guard in
vyrion rollback --framework langgraph --project ./my-agent  # undo, byte for byte
```

Every apply keeps a backup and every rollback restores the original source exactly.

## What the fix is

Vyrion installs a small **guard** next to your protected action. Before the action runs, the guard checks that the approval is a **Vyrion Seal**: a signed artifact that binds the approval to the exact action, the exact arguments, the run it belongs to, the approver, the policy, an expiry, and a one-time nonce. A forged, replayed, or tampered approval fails that check and the action does not run. The guard holds public verification keys only and fails closed.

The Seal is language agnostic. A Seal minted in Python verifies byte for byte in Node, which is how the same guarantee covers both Python and JavaScript frameworks. See [docs/concepts/cross-language-seal.md](docs/concepts/cross-language-seal.md).

## Supported frameworks

Fifteen frameworks are certified, meaning the fix was proven on a real run of each: a genuine approval passes, and forged, rebound, replayed, and bypassed approvals are all blocked.

| Tier | Frameworks |
|------|-----------|
| **Trusted run anchor** (approval bound to a run id from the runtime) | LangGraph, Apache Burr, DBOS |
| **No anchor** (approval bound to action, arguments, and a one-time nonce) | LlamaIndex, CrewAI, OpenAI Agents SDK, Google ADK, AutoGen, Haystack, Strands, Agno, Semantic Kernel, Apache Airflow, Genkit, Vercel AI |

Full detail and how each tier is decided: [docs/support-matrix.md](docs/support-matrix.md).

## Is this real? The disclosure trail

The vulnerability class is not hypothetical. It was reported to the affected vendors, and their responses are on the record. One is a published advisory; several vendors agreed the behaviour is exactly as described and placed the missing control outside their own trust boundary, which is precisely the gap Vyrion fills.

- **Flowise**: confirmed and accepted as a Medium-severity advisory (GHSA-2hjv-g5fh-6w4j).
- **Apache Burr**: PMC confirmed the finding is technically accurate and invited us to help author Burr's security model.
- **Google ADK**: reported and triaged (issue 518333638, priority P3, under review).
- **Microsoft**, **Kestra**, **AWS (Strands)**, **OpenAI**: each confirmed the behaviour and treated it as an application or operator responsibility.

Full account, with exactly what each vendor said: [docs/research/disclosures.md](docs/research/disclosures.md).

## Documentation

- [What a Ghost Approval is](docs/concepts/approval-provenance-failure.md)
- [Threat model](docs/concepts/threat-model.md)
- [How the Seal works](docs/concepts/the-seal.md)
- [The cross-language Seal](docs/concepts/cross-language-seal.md)
- [How verification works](docs/verification.md)
- [Support matrix](docs/support-matrix.md)

## Contributing

New framework adapters, testbeds, and documentation are all welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Please report security issues in Vyrion itself privately, see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Citation

If you build on this work, please cite it. See [CITATION.cff](CITATION.cff).
