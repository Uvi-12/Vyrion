"""The harness must detect, find a real chain, and produce all five technique
sections with real source evidence for every framework in the fleet."""
import pytest
from vyrion._harness import ALL_HARNESSES
from vyrion._harness.model import Technique


@pytest.mark.parametrize("h", ALL_HARNESSES, ids=[h.name for h in ALL_HARNESSES])
def test_framework_report(h):
    r = h.run()
    assert r.detected, f"{h.name} not detected in its sample"
    assert r.chains, f"{h.name} found no HITL chain"
    # every discovered chain carries real source evidence
    for c in r.chains:
        assert c.approval.evidence.start_line >= 1
        assert c.approval.evidence.path.endswith((".py", ".ts", ".js"))
    # all five techniques are represented
    techs = {s.technique for s in r.surfaces}
    assert techs == set(Technique), f"{h.name} missing technique sections: {set(Technique)-techs}"
    # applicable techniques carry at least one concrete point
    for s in r.surfaces:
        if s.applicable:
            assert s.points, f"{h.name} {s.technique} applicable but no points"


def test_fleet_size():
    assert len(ALL_HARNESSES) == 15


def test_evidence_is_not_synthesized():
    # a framework's action evidence must point at a real construct in its sample
    from vyrion._harness.registry import get_harness
    r = get_harness("LangGraph").run()
    ev = r.chains[0].action.evidence
    assert "transfer_funds" in ev.snippet
