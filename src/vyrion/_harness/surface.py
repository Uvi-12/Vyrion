"""Five-technique surface builder.

Given a discovered chain (approval -> persistence -> action) with real source
evidence, produce the concrete point where each of the five techniques could
land. Each point states the payload an attacker writes, the missing binding that
lets it through today, and the Seal binding that closes it. The labels are
supplied per framework so the sections read specifically, but the shape is
uniform because APF is one failure with five expressions.
"""

from __future__ import annotations

from .model import Chain, SurfacePoint, Technique, TechniqueSurface


def build_surface(chain: Chain, *, resistant: dict | None = None) -> list[TechniqueSurface]:
    """resistant: optional {Technique: rationale} for techniques the framework
    resists (e.g. server-owned control), which makes that section applicable=False."""
    resistant = resistant or {}
    ap, ps, act = chain.approval, chain.persistence, chain.action
    store = ps.mechanism
    marker = ps.marker_path
    action_loc = f"{act.evidence.path}:{act.evidence.start_line}"
    persist_loc = (f"{ps.evidence.path}:{ps.evidence.start_line}"
                   if ps.evidence else f"{store} ({marker})")
    approval_loc = f"{ap.evidence.path}:{ap.evidence.start_line}"

    surfaces = []

    def section(tech, applicable, rationale, points):
        surfaces.append(TechniqueSurface(technique=tech, applicable=applicable,
                                         rationale=rationale, points=points))

    # FORGE: a non-approver writes an approve marker into the persisted store.
    if Technique.FORGE in resistant:
        section(Technique.FORGE, False, resistant[Technique.FORGE], [])
    else:
        section(Technique.FORGE, True,
                f"The resume path reads the approval decision from {store} at "
                f"'{marker}' and trusts it. Any principal that can write {store} "
                f"can author the approval without approval authority.",
                [SurfacePoint(
                    location=persist_loc,
                    evidence=ps.evidence,
                    attacker_writes=f"set {marker} = <approve> in {store}",
                    why_it_works=("the decision is not bound to an authenticated "
                                  "approver or signed; presence of the marker is "
                                  "treated as authorization"),
                    binding_that_defeats_it=("Seal binds decision + approver identity "
                                             "under a signature the store writer cannot forge"))])

    # REBIND: approve stands, but the action or arguments are changed after approval.
    if Technique.REBIND in resistant:
        section(Technique.REBIND, False, resistant[Technique.REBIND], [])
    else:
        section(Technique.REBIND, True,
                f"The action '{act.id}' and its arguments ({', '.join(act.arguments) or 'n/a'}) "
                f"are read at execution from mutable state, not from the approval. "
                f"A genuine approval can be rebound to a different action or arguments.",
                [SurfacePoint(
                    location=action_loc,
                    evidence=act.evidence,
                    attacker_writes=(f"leave {marker}=<approve>; change the persisted "
                                     f"arguments of {act.id} (e.g. recipient/amount) or "
                                     f"redirect to a different action"),
                    why_it_works=("the approval does not commit to a specific action id "
                                  "or an arguments hash, so post-approval mutation is invisible"),
                    binding_that_defeats_it=("Seal binds action_id + arguments_commitment; "
                                             "verify recomputes the commitment from the actual "
                                             "invocation and rejects any change"))])

    # REPLAY: a one-time approval reused across runs/checkpoints.
    if Technique.REPLAY in resistant:
        section(Technique.REPLAY, False, resistant[Technique.REPLAY], [])
    else:
        section(Technique.REPLAY, True,
                f"The persisted approval in {store} carries no single-use token, so the "
                f"same approval can be replayed into another run, thread, or checkpoint.",
                [SurfacePoint(
                    location=persist_loc,
                    evidence=ps.evidence,
                    attacker_writes=(f"copy a genuine approved {marker} from one run into "
                                     f"another run/thread/checkpoint and resume"),
                    why_it_works=("nothing consumes the approval; there is no nonce bound "
                                  "to run/checkpoint, so it is valid more than once"),
                    binding_that_defeats_it=("Seal carries a nonce bound to run_id and "
                                             "checkpoint_id; verify consumes it atomically, "
                                             "so a second use fails closed"))])

    # SUPPRESS: skip the gate entirely by forcing the post-approval control state.
    if Technique.SUPPRESS in resistant:
        section(Technique.SUPPRESS, False, resistant[Technique.SUPPRESS], [])
    else:
        section(Technique.SUPPRESS, True,
                f"The approval point '{ap.id}' ({ap.mechanism}) can be bypassed by writing "
                f"the post-approval control state directly, so the human is never asked and "
                f"execution proceeds as if approved.",
                [SurfacePoint(
                    location=approval_loc,
                    evidence=ap.evidence,
                    attacker_writes=(f"advance {store} past the {ap.mechanism} gate "
                                     f"(set the resume/next-step state) without triggering "
                                     f"the human prompt"),
                    why_it_works=("presence in the post-gate state is sufficient to proceed; "
                                  "the gate does not require a positive signed decision to exist"),
                    binding_that_defeats_it=("execution guard fails closed when no valid Seal "
                                             "is present; skipping the gate leaves no Seal, so "
                                             "the action is blocked"))])

    # LAUNDER: the audit is generated from the same mutable state a forge already controls.
    if Technique.LAUNDER in resistant:
        section(Technique.LAUNDER, False, resistant[Technique.LAUNDER], [])
    else:
        section(Technique.LAUNDER, True,
                f"The audit/attribution for this action is derived from the same mutable "
                f"{store} state. A forged approval therefore also produces a clean audit "
                f"record naming an approver who never approved.",
                [SurfacePoint(
                    location=persist_loc,
                    evidence=ps.evidence,
                    attacker_writes=(f"forge {marker}=<approve> with approver='real.human@corp'; "
                                     f"the audit emission reads that field and records a genuine-"
                                     f"looking approval"),
                    why_it_works=("audit is emitted from mutable workflow state rather than from "
                                  "an independently signed artifact, so it inherits the forgery"),
                    binding_that_defeats_it=("audit is written from the verified Seal (signed "
                                             "approver, decision, action) via a hash-chained log, "
                                             "so a forged approval cannot produce a valid record"))])

    return surfaces
