---
name: run-autests
description: Run Apache Traffic Server AuTests correctly via autest.sh from tests/autests.
---

# AuTests

AuTests are end-to-end tests. They are Python-based but must be run through
the build-generated `autest.sh`, not by invoking Python directly. The test
descriptions are in the `tests/autests/gold_tests` directory and they have
`.test.py` extensions.

# Run AuTests

After building (see `../build-pv/SKILL.md`), run tests from the build tree:

```bash

if [ "`uname`" = "Linux" ]
then
  num_threads=$(nproc)
else
  num_threads=$(sysctl -n hw.logicalcpu)
fi
./build/dev-external/autest.sh --clean=none -j${num_threads}
```

The `--clean=none` option is used to prevent the sandbox from being cleaned up
after tests pass, which is helpful for verifying expected output from a passed
test.

An optional `--sandbox /tmp/sbpv` can be used to specify a custom sandbox
location rather than the default. The sandbox contains process logging output
which can be helpful to or otherwise diagnose test process behavior. Changing
the default location via `--sandbox` is often not necessary. If you omit
`--sandbox`, sequential runs default to `./tests/autests/_sandbox`, while
parallel runs default to `/tmp/proxy-verifier-autest`.

The `-j` option runs AuTests in parallel. Not passing `-j` will run the tests
sequentially, which is significantly slower of course. Use `-j` to speed up
running all the tests to verify that the patch didn't introduce a regression.

Individual tests can be run via the `-f` option, which takes a set of AuTests
to run, excluding their `.test.py` extension. For example, to run the
`tests/autests/gold_tests/https/https.test.py` and the
`tests/autests/gold_tests/http2/http2.test.py` tests, you would:

```bash
./build/dev-external/autest.sh -f https http2
```

The `-f` and `-j` options can be combined when you want a smaller parallel
smoke test:

```bash
./build/dev-external/autest.sh -j4 -f http https
```
