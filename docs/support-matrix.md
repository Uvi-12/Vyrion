# Support matrix

Fifteen frameworks are certified: the fix was proven on a real run of each. A framework
is only marked as anchored to a trusted run id when the framework actually exposes one at
the approval point; otherwise the Seal binds to action, arguments, and a one-time nonce.

| Framework | Language | Binding tier | Gates proven |
|---|---|---|---|
| LangGraph | Python | trusted run anchor (thread_id) | genuine passes; forge, rebind, replay, bypass blocked |
| Apache Burr | Python | trusted run anchor (app_id) | genuine passes; forge, rebind, replay, bypass blocked |
| DBOS Transact | Python | trusted run anchor (workflow_id) | genuine passes; forge, rebind, replay, bypass blocked |
| LlamaIndex Workflows | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| CrewAI Flows | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| OpenAI Agents SDK | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| Google ADK | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| AutoGen | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| Haystack | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| Strands Agents | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| Agno | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| Semantic Kernel | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| Apache Airflow | Python | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| Genkit | Node | no anchor | genuine passes; forge, rebind, replay, bypass blocked |
| Vercel AI | Node | no anchor | genuine passes; forge, rebind, replay, bypass blocked |

## What the tiers mean

- **Trusted run anchor**: the framework exposes a run identity from its runtime at the
  approval point, and the Seal is bound to it. This is the strongest binding.
- **No anchor**: the framework serializes its state as a whole and exposes no trusted run
  id at the guard, so the Seal binds to the action, its arguments, and a one-time nonce.

## Reproduce it

```
pip install "vyrion[langgraph]"
vyrion certify --framework langgraph --live
```

The two Node frameworks (Genkit, Vercel AI) need Node and `npm install genkit ai`.

