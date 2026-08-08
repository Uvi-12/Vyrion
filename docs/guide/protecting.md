# Protecting a gate

`apply` wires the guard into your project. It backs up the original source, installs the
guard next to the protected action, writes a manifest, and generates a verification key.

```
vyrion apply --framework langgraph --project ./my-agent
```

After this, the protected action verifies a Vyrion Seal before it runs. A forged,
rebound, or replayed approval is rejected and the action does not execute.

The guard holds public verification keys only. It never holds a signing key.
