---
name: run-autests
description: Run Apache Traffic Server AuTests correctly via autest.sh from test/autests.
---

# AuTests

AuTests are end-to-end tests. They are Python-based but must be run through
the build-generated `autest.sh`, not by invoking Python directly. The test
descriptions are in the `test/autests/gold_tests` directory and they have
`.test.py` extensions.

# Run AuTests

After building (see `../build-pv/SKILL.md`), run tests from the build tree:

```bash
./build/dev-external/autest.sh --sandbox /tmp/sbpv --clean=none
```

Individual tests can be run via the `-f` option, which takes a set of AuTests
to run, excluding their `.test.py` extension. For example, to run the
`test/autests/gold_tests/https/https.test.py` and the
`test/autests/gold_tests/http2/http2.test.py` tests, you would:

```bash
./build/dev-external/autest.sh --sandbox /tmp/sb --clean=none -f https http2
```
