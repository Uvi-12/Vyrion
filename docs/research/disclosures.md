# Coordinated disclosure record

Ghost Approvals are not a hypothetical. The vulnerability class was reported to the
affected vendors through their official security channels, under coordinated disclosure.
This page records what was reported and, more importantly, what each vendor said back.

Read the pattern before the individual entries. Across seven independent vendors, one
accepted and published an advisory, and the rest confirmed the behaviour is exactly as
described and located the missing control **outside their own trust boundary**: the
approval state is the operator's or application's responsibility, not the framework's.
That is not seven teams disagreeing with the finding. It is seven teams independently
confirming that binding a human approval to the action it authorized is nobody's job
today. That gap is the reason Vyrion exists.

All personal contact details have been removed. Each entry cites only public,
verifiable identifiers (advisory numbers, issue ids, commit refs).

---

## Flowise — accepted, published advisory

**Identifier:** GHSA-2hjv-g5fh-6w4j
**Status:** Accepted, Medium severity.

The finding concerns the AgentFlow v2 checkpoint blob, where the approval decision lives
in serialized `channel_values` with no integrity binding. Flowise completed triage,
confirmed a Medium-severity vulnerability, and accepted the advisory. This is the
published, third-party-verified anchor of the disclosure trail.

---

## Apache Burr — confirmed accurate, declined as a framework CVE, invited co-authorship of the security model

**Status:** Confirmed technically accurate; declined as a framework vulnerability
(no CVE) on trust-boundary grounds; the PMC invited collaboration on Burr's security model.

The report showed that a human approval stored in Burr's persisted `State` is not bound
to the action arguments it approved, so a principal with write access to the persisted
state can change the arguments after a genuine approval and before resume, and the
protected action executes the altered call under the original approval.

The Burr PMC reviewed the finding against the source (confirmed at commit `8a91bcc2`,
`burr/core/persistence.py`), agreed the technical description and reproduction are
correct, and confirmed there is no approval-binding primitive in `burr/core/`. They
declined it as a framework vulnerability, stating that the persisted `State` store is
inside the operator's trust boundary, not Burr's, and that a principal able to write
that store is a trusted principal from the framework's point of view. In the same
response they agreed Burr has no published security model and asked for guidance on
writing one.

For context, the PMC noted that a separate 2026 report on unsafe deserialization of
persisted `State` was treated as CVE-worthy by a Burr maintainer. That separate report
is not part of this disclosure and is mentioned only because the PMC raised it; it is
attributed to their statement, not claimed here.

The proposed mitigation in the report is exactly what Vyrion implements: bind the
approval to a canonical digest of the reviewed action and re-verify that binding at
execution time.

---

## Google ADK — reported and triaged, under review

**Identifier:** issuetracker.google.com issue 518333638
**Status:** Assigned, priority P3, under active review by the Google AI VRP team.

The report describes a human-in-the-loop approval bypass via session-state manipulation
in `DatabaseSessionService`: the approval decision is read back from session state on
resume with no provenance check, so a writer of that state can flip it. The issue was
triaged, its priority raised to P3, and it remains under review at the time of writing.
It is recorded here as reported-and-triaged, not as a confirmed or accepted vulnerability.

---

## Microsoft — technical characterization agreed, declined for servicing

**Identifier:** MSRC case VULN-191832 (Microsoft Agent Framework)
**Status:** Not serviced; technical characterization agreed.

The report showed that an attacker with write access to a `WorkflowCheckpoint` JSON file
can mutate a human approval gate's state, and that the framework's `graph_signature_hash`
is a topology validator rather than a tamper detector. MSRC agreed with that
characterization and agreed the mutation is possible, but classified the report out of
scope for servicing on the grounds that checkpoint storage is a documented trust boundary
the operator is responsible for, and that write access to the checkpoint file implies
equivalent access to other trusted state. The recommended hardening they point to is a
storage implementation that signs or HMACs checkpoints and verifies on read, which is the
same provenance-binding principle Vyrion applies at the approval level.

---

## Kestra — reviewed and closed as out of scope

**Identifier:** GHSA-pwpq-4x65-6rhf
**Status:** Closed, not considered a vulnerability in Kestra.

The report concerned a paused execution resuming without binding the resume to an
approver decision. Kestra confirmed that the `resumed.by` / `resumed.on` / `resumed.to`
fields are provenance for the resume path, not an authorization control, and that direct
edits to the internal state store require database credentials and therefore sit outside
Kestra's trust boundary. They pointed to `HumanTask` with an assignment block plus RBAC
and audit logs for gates that must be bound to named approvers.

---

## AWS — Strands Agents SDK — acknowledged, closed as informative

**Identifier:** AWS VDP / HackerOne report #3883515
**Status:** Closed as Informative; behaviour confirmed.

The report showed that persisted agent state containing `hitl:trusted_tools` entries is
honoured on restore even when `enable_trust=False`. AWS confirmed the behaviour and
placed it under the shared-responsibility model: securing the state store and validating
state integrity on restore is the deploying developer's responsibility. The submission
and its executable reproduction were acknowledged as high quality.

---

## OpenAI — Agents SDK — engaged, resolved on the documentation track

**Status:** Treated as application-owned state; agreed documentation guidance is warranted.

The report showed that a tool marked `needs_approval=True` stores its approval decision in
the serialized `RunState` (`to_json` / `from_json`) with no integrity check, so a writer
of that state can set `approved: true` and the gate is skipped on resume. OpenAI's
position is that the serialized state is application-owned and outside the current threat
model, and they agreed that documentation guidance on integrity-protecting approval state
before trusting it for gated actions would be useful. The suggested guidance is to bind
approval decisions to the run, the tool and arguments, the approver identity, and the
execution context, and to verify that binding before resume, which is what the Vyrion
Seal encodes.

---

## What this record supports

- The behaviour is real and reproducible, confirmed on the record by every vendor contacted.
- One vendor (Flowise) accepted and published an advisory for it.
- The rest agree the missing control is a real gap and place it outside the framework's
  responsibility, which means today it is nobody's: not the framework's, and not something
  application developers have a primitive to implement.
- Vyrion is that primitive, and the [support matrix](../support-matrix.md) shows it working
  on fifteen frameworks including the ones named here.
