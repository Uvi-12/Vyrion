# Scanning a project

Point Vyrion at a folder and it detects the framework, finds the approval gate, and
reports whether it is exposed.

```
vyrion run ./my-agent
```

To see the same detection as part of certification for a known framework:

```
vyrion certify --framework langgraph
```

Scanning is read-only. Nothing is changed until you run `apply`.
