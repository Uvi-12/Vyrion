# Rollback

Undo an apply and restore the project exactly as it was:

```
vyrion rollback --framework langgraph --project ./my-agent
```

Rollback restores the original source byte for byte and removes the guard, the manifest,
and the generated keys. Verification includes a byte-identical rollback check, so a clean
undo is part of what "certified" means.
