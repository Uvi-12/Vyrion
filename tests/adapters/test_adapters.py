"""Native adapter certification tests.

Environment-aware: a dedicated adapter (LangGraph, LlamaIndex) reaches Native
Certified only on a host where its framework is installed and the live gates run
here; on a host without it, it is Native Ready with the live gates pending. Every
other adapter completes all non-live gates with the live gates pending a host.
No adapter may report a spurious FAIL in any environment.
"""
import importlib.util
import shutil, tempfile
from pathlib import Path
import pytest
from vyrion.engine.verification import certify, GateStatus
from vyrion.engine.registry import build_fleet, target_for


def _installed(mod):
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


LANGGRAPH = _installed("langgraph")
LLAMAINDEX = _installed("llama_index.core")


_DEDICATED_SAMPLE = {"LangGraph": "langgraph", "LlamaIndex Workflows": "llamaindex",
                     "Apache Burr": "burr", "DBOS Transact": "dbos", "CrewAI Flows": "crewai", "OpenAI Agents SDK": "openai_agents", "Google ADK": "google_adk", "AutoGen": "autogen", "Haystack": "haystack", "Strands Agents": "strands", "Agno": "agno", "Semantic Kernel": "semantic_kernel", "Apache Airflow": "airflow", "Genkit": "genkit", "Vercel AI": "vercel_ai"}


def _sample_of(a):
    if hasattr(a, "spec"):
        return a.spec.sample_dir
    return _DEDICATED_SAMPLE[a.framework]


def _run(adapter):
    tmp = Path(tempfile.mkdtemp()) / "proj"
    shutil.copytree(target_for(_sample_of(adapter)), tmp)
    return certify(adapter, str(tmp))


def _expected_tier(adapter):
    if adapter.framework in ("Genkit", "Vercel AI"):
        import shutil as _sh
        node = _sh.which("node") is not None
        nm = None
        try:
            from vyrion.engine.registry import target_for
            key = {"Genkit": "genkit", "Vercel AI": "vercel_ai"}[adapter.framework]
            nm = adapter._find_node_modules(str(target_for(key)))
        except Exception:
            nm = None
        return "Native Certified" if (node and nm) else "Native Ready"

    if "LangGraph" in adapter.framework:
        return "Native Certified" if LANGGRAPH else "Native Ready"
    if "LlamaIndex" in adapter.framework:
        return "Native Certified" if LLAMAINDEX else "Native Ready"
    if "Burr" in adapter.framework:
        return "Native Certified" if _installed("burr") else "Native Ready"
    if "DBOS" in adapter.framework:
        return "Native Certified" if _installed("dbos") else "Native Ready"
    if "CrewAI" in adapter.framework:
        return "Native Certified" if _installed("crewai") else "Native Ready"
    if "OpenAI Agents" in adapter.framework:
        return "Native Certified" if _installed("agents") else "Native Ready"
    if "Google ADK" in adapter.framework:
        return "Native Certified" if _installed("google.adk") else "Native Ready"
    if adapter.framework == "AutoGen":
        return "Native Certified" if _installed("autogen_core") else "Native Ready"
    if adapter.framework == "Haystack":
        return "Native Certified" if _installed("haystack") else "Native Ready"
    if "Strands" in adapter.framework:
        return "Native Certified" if _installed("strands") else "Native Ready"
    if adapter.framework == "Agno":
        return "Native Certified" if _installed("agno") else "Native Ready"
    if "Semantic Kernel" in adapter.framework:
        return "Native Certified" if _installed("semantic_kernel") else "Native Ready"
    if "Airflow" in adapter.framework:
        return "Native Certified" if _installed("airflow") else "Native Ready"
    return "Native Ready"


FLEET = build_fleet()


@pytest.mark.parametrize("adapter,_expected", FLEET, ids=[a.framework for a, _ in FLEET])
def test_no_gate_fails(adapter, _expected):
    cert = _run(adapter)
    fails = [g.id for g in cert.gates if g.status == GateStatus.FAIL]
    assert not fails, f"{adapter.framework} failed gates {fails}"
    assert cert.tier == _expected_tier(adapter)


def test_fleet_is_fifteen_all_native():
    tiers = [_run(a).tier for a, _ in FLEET]
    assert len(tiers) == 15
    # every row is native (certified or ready); none incomplete
    assert all(t in ("Native Certified", "Native Ready") for t in tiers)


@pytest.mark.skipif(not LANGGRAPH, reason="LangGraph not installed")
def test_langgraph_certified_live_here():
    ad = next(a for a, _ in FLEET if "LangGraph" in a.framework)
    cert = _run(ad)
    assert cert.tier == "Native Certified"
    assert cert.runtime_status == "executed_here"
    live = {g.id: g for g in cert.gates if g.id in ("N13", "N14", "N15", "N16", "N17")}
    assert live["N13"].detail == "genuine=ALLOWED"
    assert live["N14"].detail == "forge=BLOCKED"
    assert live["N16"].detail == "concurrent_replay=ONE"


@pytest.mark.skipif(not LLAMAINDEX, reason="LlamaIndex not installed")
def test_llamaindex_certified_live_here():
    ad = next(a for a, _ in FLEET if "LlamaIndex" in a.framework)
    cert = _run(ad)
    assert cert.tier == "Native Certified"
    assert cert.runtime_status == "executed_here"
    live = {g.id: g for g in cert.gates if g.id in ("N13", "N14", "N16")}
    assert live["N13"].detail == "genuine=ALLOWED"
    assert live["N16"].detail == "concurrent_replay=ONE"


def test_ready_marks_live_pending_not_passed():
    for adapter, _ in FLEET:
        if _expected_tier(adapter) != "Native Ready":
            continue
        cert = _run(adapter)
        for g in cert.gates:
            if g.id in ("N13", "N14", "N15", "N16", "N17"):
                assert g.status == GateStatus.PENDING_LIVE


def test_every_native_ready_actually_patches_source():
    """Native Ready must mean real source wiring (N10 pass), not a static scaffold."""
    for adapter, _ in FLEET:
        cert = _run(adapter)
        n10 = next(g for g in cert.gates if g.id == "N10")
        assert n10.status == GateStatus.PASS, f"{adapter.framework} N10={n10.detail}"
