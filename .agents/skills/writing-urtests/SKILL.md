---
name: writing-urtests
description: Guidance for adding Proxy Verifier pytest-based end-to-end tests.
---

# Write Uranium Tests

Uranium is Proxy Verifier's pytest-based end-to-end test framework.

- Put tests under `tests/uranium_tests` in ordinary `test_*.py` modules.
- Use `CaseSuite` and the process helpers from `tools.uranium`.
- Treat replay YAML, JSON, and gold files as data referenced by Python tests;
  they are not collected directly.
- Use existing modules under `tests/uranium_tests` for examples.
- Run tests through the build-generated `urtest.sh` wrapper described in
  `../run-urtests/SKILL.md`.

## Process Expectations

Register output expectations through the explicit stream API. Both regex
methods require an explanation that describes the intended behavior and is
reported when the expectation fails.

```python
server.stdout.contains(
    "Ready with 3 transactions",
    "The server should parse all three transactions.",
)
server.stdout.excludes(
    "Violation:",
    "The server should not report verification errors.",
)
server.stdout.matches_gold("gold/server.gold")
```

Use `server.stdout.reset()` to intentionally discard all expectations already
registered for that stream. The reset affects expectations only; it does not
change the captured output path.

The `stdout` and `stderr` properties are read-only. Do not use `=` or `+=` to
register expectations. Configure acceptable process exit statuses explicitly:

```python
client.expect_return_codes(0, 1)
```
