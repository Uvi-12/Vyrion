# How verification works

Vyrion does not ask you to trust that the fix works. It **proves** it on a real run of
each framework, and calls a framework *certified* only when that proof actually executed.

## The five live gates

For each framework, Vyrion runs the real framework and checks:

- **Genuine approval passes.** A correctly signed Seal lets the action run.
- **Forge is blocked.** A fabricated approval does not run the action.
- **Rebind is blocked.** A genuine approval with altered arguments does not run.
- **Replay is blocked.** A genuine approval cannot be used twice; exactly one run wins.
- **Bypass is blocked.** Forcing execution without a valid Seal fails closed.

These are gates N13 through N17 in the internal check set. The full set (N1 through N20)
also covers detection, evidence, patch correctness, key handling, and byte-identical
rollback.

## Certified vs ready

- **Native Certified** means the live gates actually ran on this host, against the real
  installed framework, and passed.
- **Native Ready** means everything except the live run is proven, but the framework is
  not installed here, so the live gates are pending. Install the framework's extra and
  re-run to complete certification.

Run it yourself:

```
vyrion certify --framework langgraph --live
```

Generate the whole matrix as a file:

```
vyrion certify --json --out matrix.json
```

## Two binding tiers, labelled honestly

A framework is only anchored to a trusted run id if the framework actually exposes one at
the approval point. Where it does not, Vyrion says so and binds to action, arguments, and
a one-time nonce instead. The tool never claims an anchor a framework does not provide.
