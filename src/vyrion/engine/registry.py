"""The native adapter fleet: 2 fully-certified here, 13 native-ready for a host.

Maps each supported framework to its adapter. LangGraph and LlamaIndex have
dedicated adapters whose live gates run in this environment. The other thirteen
use spec-driven adapters that do everything except the live gates, which they
mark PENDING_LIVE with the exact host requirement and command.
"""

from __future__ import annotations

from .._harness.registry import ALL_HARNESSES
from .adapters.langgraph import LangGraphNativeAdapter
from .adapters.llamaindex import LlamaIndexNativeAdapter
from .adapters.burr import BurrNativeAdapter
from .adapters.dbos import DBOSNativeAdapter
from .adapters.crewai import CrewAINativeAdapter
from .adapters.openai_agents import OpenAIAgentsNativeAdapter
from .adapters.google_adk import GoogleADKNativeAdapter
from .adapters.autogen import AutoGenNativeAdapter
from .adapters.haystack import HaystackNativeAdapter
from .adapters.strands import StrandsNativeAdapter
from .adapters.agno import AgnoNativeAdapter
from .adapters.semantic_kernel import SemanticKernelNativeAdapter
from .adapters.airflow import AirflowNativeAdapter
from .adapters.genkit import GenkitNativeAdapter
from .adapters.vercel_ai import VercelAINativeAdapter
from .adapters.generic import SpecNativeAdapter, NodeSpecNativeAdapter

# host requirements to complete N13-N17 for each native-ready framework
HOST_REQS = {
    "crewai": "pip install crewai (Python 3.10+); a CrewAI flow with a human input step",
    "autogen": "pip install autogen-agentchat autogen-core (Python 3.10+)",
    "semantic_kernel": "pip install semantic-kernel; PyJWT resolvable (venv, not system apt)",
    "openai_agents": "pip install openai-agents; an interruption/approval tool call",
    "google_adk": "pip install google-adk; a LongRunningFunctionTool approval",
    "agno": "pip install agno; a tool with requires_confirmation=True",
    "haystack": "pip install haystack-ai; a pipeline breakpoint / resume",
    "strands": "pip install strands-agents; a tool approval hook",
    "burr": "pip install burr; an application with a persisted approval state",
    "airflow": "pip install apache-airflow; a DAG with an approval gate task",
    "dbos": "pip install dbos; a durable workflow with a recv() approval step",
    "genkit": "Node 18+; npm i genkit; a flow with an interrupt",
    "vercel_ai": "Node 18+; npm i ai; a tool with needsApproval",
}

_DEDICATED = {"langgraph": LangGraphNativeAdapter, "llamaindex": LlamaIndexNativeAdapter,
              "burr": BurrNativeAdapter,
              "dbos": DBOSNativeAdapter,
              "crewai": CrewAINativeAdapter,
              "openai_agents": OpenAIAgentsNativeAdapter,
              "google_adk": GoogleADKNativeAdapter,
              "autogen": AutoGenNativeAdapter,
              "haystack": HaystackNativeAdapter,
              "strands": StrandsNativeAdapter,
              "agno": AgnoNativeAdapter,
              "semantic_kernel": SemanticKernelNativeAdapter,
              "airflow": AirflowNativeAdapter,
              "genkit": GenkitNativeAdapter,
              "vercel_ai": VercelAINativeAdapter}


def _harness_by_dir():
    out = {}
    for h in ALL_HARNESSES:
        out[h.spec.sample_dir] = h, getattr(h, "language", "python")
    return out


def build_fleet():
    """Return an ordered list of (adapter, expected_tier_here)."""
    harnesses = _harness_by_dir()
    fleet = []
    order = ["langgraph", "llamaindex", "crewai", "autogen", "semantic_kernel",
             "openai_agents", "google_adk", "agno", "haystack", "strands", "burr",
             "airflow", "dbos", "genkit", "vercel_ai"]
    for name in order:
        harness, lang = harnesses[name]
        if name in _DEDICATED:
            fleet.append((_DEDICATED[name](), "Native Certified"))
        elif lang == "typescript":
            fleet.append((NodeSpecNativeAdapter(
                harness, HOST_REQS.get(name, "Node runtime + framework"),
                f"vyrion-{name}"), "Native Ready"))
        else:
            fleet.append((SpecNativeAdapter(
                harness, HOST_REQS.get(name, "framework installed on host"),
                f"vyrion-{name}"), "Native Ready"))
    return fleet


def target_for(sample_dir: str):
    """Return the pristine sample project path for a framework."""
    from pathlib import Path
    base = Path(__file__).parent.parent
    if sample_dir == "langgraph":
        return base / "_fixtures" / "langgraph"
    if sample_dir == "llamaindex":
        return base / "_fixtures" / "llamaindex"
    if sample_dir == "burr":
        return base / "_fixtures" / "burr"
    if sample_dir == "dbos":
        return base / "_fixtures" / "dbos"
    if sample_dir == "crewai":
        return base / "_fixtures" / "crewai"
    if sample_dir == "openai_agents":
        return base / "_fixtures" / "openai_agents"
    if sample_dir == "google_adk":
        return base / "_fixtures" / "google_adk"
    if sample_dir == "autogen":
        return base / "_fixtures" / "autogen"
    if sample_dir == "haystack":
        return base / "_fixtures" / "haystack"
    if sample_dir == "strands":
        return base / "_fixtures" / "strands"
    if sample_dir == "agno":
        return base / "_fixtures" / "agno"
    if sample_dir == "semantic_kernel":
        return base / "_fixtures" / "semantic_kernel"
    if sample_dir == "airflow":
        return base / "_fixtures" / "airflow"
    if sample_dir == "genkit":
        return base / "_fixtures" / "genkit"
    if sample_dir == "vercel_ai":
        return base / "_fixtures" / "vercel_ai"
    return base.parent / "_harness" / "samples" / sample_dir

# vyrion-build: 15-frameworks COMPLETE incl. Genkit + VercelAI


def get_adapter(name):
    """Return a dedicated adapter instance by registry key (e.g. 'genkit').
    Falls back to the spec-driven generic adapter when no dedicated one exists."""
    key = name.lower().replace('-', '_')
    if key in _DEDICATED:
        return _DEDICATED[key]()
    for a, _ in build_fleet():
        if getattr(a, 'framework', '').lower().replace(' ', '_').replace('-', '_') == key:
            return a
    raise KeyError(name)
