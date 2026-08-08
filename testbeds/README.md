# Testbeds

Each folder is a small, realistic project for one framework, with a human approval gate
that is vulnerable to a Ghost Approval. They are the full environments the adapters and CI
certify against.

To certify a framework against its testbed:

```
pip install "vyrion[langgraph]"
vyrion certify --framework langgraph --live
```

For the two Node frameworks:

```
npm install genkit ai
vyrion certify --framework genkit --live
```

The minimal, packaged versions of these apps also ship inside the wheel (under
`vyrion/_fixtures/`) so `vyrion certify` works after a plain `pip install vyrion`, without
this repository checked out.
