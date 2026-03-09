---
name: run-unit-tests
description: Build and run Proxy Verifier unit tests with CMake and CTest.
---

# Run Unit Tests

Proxy Verifier unit tests are built through CMake and run through CTest.

## Dependency location

Assume the external libraries are already installed in `/opt/pv_libs`. If they
are missing, use ../build-pv/SKILL.md first.

## Command

Build Proxy Verifier (see ../build-pv/SKILL.md) and then run the unit tests from the repo root:

```bash
cmake --preset dev-external
cmake --build --preset dev-external --parallel
ctest --preset dev-external
```

## Repo-specific notes

- The current working external dependency preset uses `PV_DEPS_ROOT=/opt/pv_libs`.
- The build-tree unit test executable is emitted under `build/<preset>/bin/`.
