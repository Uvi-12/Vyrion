"""The 15-framework harness fleet.

Every framework here is EXPOSED and native-verified across the five techniques in
the research ledgers. Two (LangGraph, LlamaIndex Workflows) are also taken to full
native certification elsewhere; here they run the same discovery so their reports
match the fleet.
"""

from __future__ import annotations

from .base import FrameworkHarness
from .pyagent import AgentSpec, PyAgentHarness
from .nodeagent import NodeSpec, NodeAgentHarness

_AGENTS = [
    AgentSpec(name="LangGraph", category="agentic-python", ledger_name="LangGraph",
              detect_imports={"langgraph"}, approval_calls={"interrupt"},
              action_decorators=set(), action_calls={"transfer_funds"},
              approval_mechanism="interrupt()", persistence_mechanism="LangGraph checkpointer",
              marker_path="channel_values.approval", resume_mechanism="Command(resume=...)",
              action_id="payments.transfer", package_name="langgraph", sample_dir="langgraph"),
    AgentSpec(name="LlamaIndex Workflows", category="agentic-python",
              ledger_name="LlamaIndex Workflows", detect_imports={"llama_index"},
              approval_calls={"InputRequiredEvent"}, action_decorators={"step"},
              approval_mechanism="InputRequiredEvent / HumanResponseEvent",
              persistence_mechanism="workflow Context store",
              marker_path="ctx.store.approval", resume_mechanism="HumanResponseEvent",
              action_id="payments.transfer", package_name="llama-index-core",
              sample_dir="llamaindex"),
    AgentSpec(name="CrewAI", category="agentic-python", ledger_name="CrewAI",
              detect_imports={"crewai"}, approval_kwflags={"human_input"},
              approval_mechanism="Task(human_input=True)",
              persistence_mechanism="CrewAI flow state", marker_path="state.approval",
              resume_mechanism="flow resume", action_id="payments.transfer",
              package_name="crewai", sample_dir="crewai"),
    AgentSpec(name="AutoGen", category="agentic-python", ledger_name="AutoGen",
              detect_imports={"autogen_agentchat", "autogen_core"},
              approval_calls={"UserProxyAgent"}, action_calls={"transfer_funds"},
              approval_mechanism="UserProxyAgent human handoff",
              persistence_mechanism="team saved state (save_state/load_state)",
              marker_path="state.approvals", resume_mechanism="load_state + resume",
              action_id="payments.transfer", package_name="autogen-agentchat",
              sample_dir="autogen"),
    AgentSpec(name="Semantic Kernel", category="agentic-python",
              ledger_name="Semantic Kernel", detect_imports={"semantic_kernel"},
              approval_defs={"request_approval"}, action_calls={"transfer_funds"},
              action_decorators={"kernel_function"},
              approval_mechanism="process approval step",
              persistence_mechanism="process framework state",
              marker_path="state.approval", resume_mechanism="process resume",
              action_id="payments.transfer", package_name="semantic-kernel",
              sample_dir="semantic_kernel"),
    AgentSpec(name="OpenAI Agents SDK", category="agentic-python",
              ledger_name="OpenAI Agents SDK", detect_imports={"agents"},
              approval_kwflags={"needs_approval"}, action_decorators={"function_tool"},
              approval_mechanism="function_tool(needs_approval=True)",
              persistence_mechanism="RunState serialization (to_json/from_json)",
              marker_path="context.approvals.<tool>.approved",
              resume_mechanism="RunState resume", action_id="payments.transfer",
              package_name="openai-agents", sample_dir="openai_agents"),
    AgentSpec(name="Google ADK", category="agentic-python", ledger_name="Google ADK",
              detect_imports={"google.adk"}, approval_defs={"before_tool_approval"},
              action_calls={"transfer_funds"},
              approval_mechanism="before_tool confirmation callback",
              persistence_mechanism="session state (SessionService)",
              marker_path="session.state.approval", resume_mechanism="session event resume",
              action_id="payments.transfer", package_name="google-adk",
              sample_dir="google_adk"),
    AgentSpec(name="Agno", category="agentic-python", ledger_name="Agno",
              detect_imports={"agno"}, approval_kwflags={"requires_confirmation"},
              action_decorators={"tool"},
              approval_mechanism="requires_confirmation tool",
              persistence_mechanism="run/session state", marker_path="run.confirmation",
              resume_mechanism="continue_run()", action_id="payments.transfer",
              package_name="agno", sample_dir="agno"),
    AgentSpec(name="Haystack", category="agentic-python", ledger_name="Haystack",
              detect_imports={"haystack"}, approval_calls={"Breakpoint"},
              action_calls={"transfer_funds"},
              approval_mechanism="pipeline breakpoint / snapshot",
              persistence_mechanism="AgentSnapshot serialization",
              marker_path="snapshot.tool_approval", resume_mechanism="resume from snapshot",
              action_id="payments.transfer", package_name="haystack-ai",
              sample_dir="haystack"),
    AgentSpec(name="Strands Agents SDK", category="agentic-python",
              ledger_name="Strands Agents SDK", detect_imports={"strands"},
              approval_kwflags={"enable_trust"}, action_decorators={"tool"},
              approval_mechanism="HITL trusted_tools",
              persistence_mechanism="persisted agent state",
              marker_path="state.hitl.trusted_tools", resume_mechanism="session restore",
              action_id="payments.transfer", package_name="strands-agents",
              sample_dir="strands"),
    AgentSpec(name="Apache Burr", category="agentic-python", ledger_name="Apache Burr",
              detect_imports={"burr"}, approval_defs={"request_approval"},
              action_calls={"transfer_funds"}, action_decorators={"action"},
              approval_mechanism="interrupt action",
              persistence_mechanism="Burr state persister",
              marker_path="state.approval", resume_mechanism="application resume",
              action_id="payments.transfer", package_name="burr", sample_dir="burr"),
    # durable engines (python AST too)
    AgentSpec(name="Apache Airflow", category="durable", ledger_name="Apache Airflow",
              detect_imports={"airflow"}, approval_calls={"HITLOperator"},
              action_calls={"transfer_funds"}, action_decorators={"task"},
              approval_mechanism="HITLOperator",
              persistence_mechanism="XCom / Variable in metadata DB",
              marker_path="xcom.request_approval.approval", resume_mechanism="downstream task run",
              action_id="payments.transfer",
              action_arguments=["recipient", "amount", "currency"],
              package_name="apache-airflow", sample_dir="airflow"),
    AgentSpec(name="DBOS Transact", category="durable", ledger_name="DBOS Transact",
              detect_imports={"dbos"}, approval_calls={"request_approval", "get_event"},
              action_calls={"transfer_funds"},
              approval_mechanism="DBOS.get_event approval / step",
              persistence_mechanism="DBOS system database",
              marker_path="workflow.events.approval", resume_mechanism="durable resume",
              action_id="payments.transfer", package_name="dbos", sample_dir="dbos"),
]

_NODE = [
    NodeSpec(name="Genkit", category="agentic-node", ledger_name="Genkit",
             detect_patterns=[r"genkit", r"defineFlow"],
             approval_patterns=[(r"interrupt\s*\(", "interrupt() call"),
                                (r"resumed", "resume handler")],
             action_patterns=[(r"defineTool", "defineTool protected action"),
                              (r"transferFunds", "transferFunds call")],
             approval_mechanism="flow interrupt()",
             persistence_mechanism="Genkit flow state",
             marker_path="flowState.approval", resume_mechanism="resumed input",
             action_id="transferFunds", sample_dir="genkit"),
    NodeSpec(name="Vercel AI SDK", category="agentic-node", ledger_name="Vercel AI SDK",
             detect_patterns=[r"from\s+['\"]ai['\"]", r"\btool\s*\("],
             approval_patterns=[(r"needsApproval\s*:", "needsApproval flag")],
             action_patterns=[(r"execute\s*:", "tool execute()")],
             approval_mechanism="tool needsApproval",
             persistence_mechanism="persisted tool-call state",
             marker_path="toolCall.approved", resume_mechanism="resume with approval",
             action_id="transferFunds", sample_dir="vercel_ai"),
]

ALL_HARNESSES: list[FrameworkHarness] = (
    [PyAgentHarness(s) for s in _AGENTS] + [NodeAgentHarness(s) for s in _NODE]
)


def get_harness(name: str) -> FrameworkHarness | None:
    for h in ALL_HARNESSES:
        if h.name.lower() == name.lower():
            return h
    return None


def run_all(project_override: str | None = None):
    return [h.run(project_override) for h in ALL_HARNESSES]
