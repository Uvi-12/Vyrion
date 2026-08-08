"""Applying twice (or run then apply) must still roll back to the byte-identical original."""
import shutil

from vyrion.engine.registry import target_for
from vyrion.engine.adapters import LangGraphNativeAdapter


def test_double_apply_rolls_back_byte_identical(tmp_path):
    proj = tmp_path / "proj"
    shutil.copytree(target_for("langgraph"), proj)
    src = proj / "payment_agent.py"
    pristine = src.read_bytes()

    a = LangGraphNativeAdapter()

    def apply_once():
        det = a.detect_project(str(proj))
        assert det.detected
        ap = a.discover_approval_points(str(proj))[0]
        tr = a.trace_actions(str(proj), ap)[0]
        patch = a.generate_patch(str(proj), tr)
        return a.apply_patch(str(proj), patch)

    apply_once()
    applied = apply_once()
    a.rollback(str(proj), applied)

    assert src.read_bytes() == pristine, "rollback did not restore the byte-identical original"
