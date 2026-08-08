"""Level 1 universal enforcement proof.

After the guard is applied to a project, the shared enforcement boundary must
allow a genuine Seal and block a missing, cross-run, replayed, or argument
tampered one, using the project's own manifest and without running any
framework node. This is the property `vyrion run` proves on a real repo.
"""
import shutil

import pytest

from vyrion.engine.registry import target_for
from vyrion.engine.adapters import LangGraphNativeAdapter
from vyrion.engine.protection.enforcement_proof import prove_enforcement


def _apply(adapter, proj):
    det = adapter.detect_project(str(proj))
    assert det.detected
    ap = adapter.discover_approval_points(str(proj))[0]
    tr = adapter.trace_actions(str(proj), ap)[0]
    patch = adapter.generate_patch(str(proj), tr)
    return adapter.apply_patch(str(proj), patch)


def test_enforcement_proof_holds_on_applied_project(tmp_path):
    proj = tmp_path / "proj"
    shutil.copytree(target_for("langgraph"), proj)
    applied = _apply(LangGraphNativeAdapter(), proj)
    assert applied is not None

    results, passed = prove_enforcement(str(proj))
    assert results["genuine"] == "ALLOWED", results
    for gate in ("forged", "cross_context", "replayed", "arg_tampered"):
        assert results[gate] == "BLOCKED", (gate, results)
    assert passed is True


def test_enforcement_proof_unavailable_before_apply(tmp_path):
    from vyrion.engine.protection.enforcement_proof import ProofUnavailable
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ProofUnavailable):
        prove_enforcement(str(empty))
