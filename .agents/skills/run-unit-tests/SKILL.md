---
name: run-unit-tests
description: Build and run Proxy Verifier unit tests with CMake and CTest.
---

# Run Unit Tests

Proxy Verifier unit tests are built through CMake and run through CTest.

## Command

Build Proxy Verifier (see ../build-pv/SKILL.md) and then run the unit tests from the repo root:

```bash
cmake --preset dev
cmake --build --preset dev --parallel
ctest --preset dev
```

## Repo-specific notes

- The build-tree unit test executable is emitted under `build/<preset>/bin/`.
