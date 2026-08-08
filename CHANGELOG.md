# Changelog

All notable changes to Vyrion are documented here. This project follows
[Semantic Versioning](https://semver.org).

## [0.2.2-beta]

### Fixed
- Deterministic resolution: file discovery in all fifteen adapters now sorts its
  results, so scanning a project resolves the same approval point and protected
  action on every run and on every operating system. Previously the choice
  depended on filesystem walk order and could differ between machines.

## [0.2.1-beta]

Robustness fixes and a universal enforcement proof for real third-party projects.

### Added
- Universal enforcement proof: after `vyrion run` applies the guard to a real
  project, it now exercises five provenance gates directly against the installed
  guard and broker using that project's own manifest, a genuine Seal is allowed,
  and a missing, cross-run, replayed, or argument-tampered one is blocked. It runs
  no framework node and needs no model key, so it proves the shared enforcement
  boundary identically for every supported Python framework.

### Fixed
- LangGraph action tracing now follows `add_conditional_edges` (router plus path
  map or router return values), not only direct `add_edge` calls, so the protected
  action is resolved in graphs that route the approval decision through a router.
- The action fallback now recognizes asynchronous nodes and nodes that read a
  `decision` or `status` field, not only a field literally named `approval`.
- `vyrion run` no longer raises an unhandled error when it detects an approval
  point but cannot resolve the protected action; it now reports the situation and
  exits cleanly.

## [0.2.0-beta]

First public beta.

### Added
- Fifteen certified framework adapters: LangGraph, LlamaIndex, Apache Burr, DBOS,
  CrewAI, OpenAI Agents SDK, Google ADK, AutoGen, Haystack, Strands, Agno,
  Semantic Kernel, Apache Airflow, Genkit, and Vercel AI.
- The Vyrion Seal: a signed approval artifact binding approval to action, arguments,
  run, approver, policy, audience, expiry, and a one-time nonce.
- A language-agnostic guard: a Python-minted Seal verifies byte for byte in Node,
  covering both Python and JavaScript frameworks with one guarantee.
- The `vyrion` CLI: `run`, `demo`, `certify`, `apply`, `rollback`, `test-guard`.
- Per-framework install extras so framework dependency pins never collide.
- Coordinated disclosure record for seven vendors.

### Notes
- Beta software. Active commands change files in the target project; every change is
  backed up and every rollback restores the original source byte for byte.
