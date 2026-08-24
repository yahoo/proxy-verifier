---
name: run-urtests
description: Run Proxy Verifier end-to-end tests with the build-generated pytest wrapper.
---

# Uranium Tests

Uranium tests are pytest-based end-to-end tests. Run them through the
build-generated `urtest.sh` so the correct binaries, plugins, and sandbox are
selected. Tests are ordinary `test_*.py` modules under `tests/uranium_tests`.

# Run Uranium Tests

After building (see `../build-pv/SKILL.md`), run tests from the build tree:

```bash

if [ "`uname`" = "Linux" ]
then
  num_threads=$(nproc)
else
  num_threads=$(sysctl -n hw.logicalcpu)
fi
./build/dev/urtest.sh -n "${num_threads}"
```

An optional `--sandbox /tmp/sbpv` can be used to specify a custom sandbox
location rather than the default. The sandbox contains process logging output
which can help diagnose process behavior. Passed-case sandboxes are removed;
failed-case sandboxes are retained.

The `-n` option runs tests in parallel. Omit it for a sequential run.

Use pytest's `-k` option to select tests by name. For example, to run the HTTPS
and HTTP/2 modules:

```bash
./build/dev/urtest.sh -k 'https or http2'
```

The `-k` and `-n` options can be combined when you want a smaller parallel
smoke test:

```bash
./build/dev/urtest.sh -n 4 -k 'http or https'
```
