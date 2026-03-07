---
name: run-unit-tests
description: Build and run Proxy Verifier unit tests with scons.
---

# Run Unit Tests

Proxy Verifier unit tests are built and run through the `run_utest` SCons
target.

## Dependency location

Assume the external libraries are already installed in `/opt/pv_libs`. If they
are missing, use
[$build-pv](/Users/bneradt/project_not_synced/codex/fix_tickets_4/proxy-verifier/.agents/skills/build-pv/SKILL.md)
first.

## macOS environment

On macOS, prefer Apple clang and export the SDK path before invoking `scons`:

```bash
export CC="$(xcrun -find clang)"
export CXX="$(xcrun -find clang++)"
export SDKROOT="$(xcrun --show-sdk-path)"
```

## Command

Run the unit tests from the repo root:

```bash
uv run scons -j 8 --with-libs=/opt/pv_libs run_utest::
```

If you want to scale parallelism by host:

```bash
if [ "$(uname)" = "Linux" ]
then
  num_threads=$(nproc)
else
  num_threads=$(sysctl -n hw.logicalcpu)
fi
uv run scons -j${num_threads} --with-libs=/opt/pv_libs run_utest::
```

## Repo-specific notes

- The current working invocation uses `--with-libs=/opt/pv_libs`.
- The README still documents the older per-library flags for unit tests; prefer
  the consolidated `--with-libs` form above.
- The unit-test target depends on external include paths from `openssl`,
  `nghttp2`, `ngtcp2`, `nghttp3`, and `yaml-cpp`. If headers are unexpectedly
  missing, check `test/unit_tests/unit_tests.part`.
