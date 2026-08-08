# Contributing to Vyrion

Thanks for helping make human approval something an attacker cannot forge.

## Getting set up

```
git clone https://github.com/Uvi-12/vyrion
cd vyrion
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Ways to help

- **New framework adapters.** If a framework has a human-in-the-loop or approval gate,
  it can probably be covered. Start from an existing adapter in
  `src/vyrion/engine/adapters/` and its testbed in `testbeds/`.
- **Testbeds.** Realistic vulnerable apps make the certification honest. See
  `testbeds/README.md`.
- **Documentation.** Clear writing about the vulnerability class helps more people
  find and fix it.

## Before you open a pull request

- Run `pytest` and `ruff check .`.
- Keep the guard honest: it must hold public verification keys only, and it must fail
  closed. No change should let a forged, replayed, or tampered approval run an action.
- No `print` debugging left in adapters.

## Reporting security issues

Please do not open a public issue for a vulnerability in Vyrion itself. See
[SECURITY.md](SECURITY.md).
