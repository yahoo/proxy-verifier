---
name: writing-autests
description: Guidance for adding Proxy Verifier autests, the end to end tests.
---

# Write ATS AuTests

AuTest is an end to end testing framework documented here:
https://autestsuite.bitbucket.io/

- Tests exis in the `test/autests/gold_tests` directory. 
- The extensions to AuTest specific to Proxy Verifier are in the `test/autests/gold_tests/autest-site` directory.
- Tests end with the `.test.py` extension.
- When writing new tests, view the existing `test/autests/gold_tests` `.test.py` files for inspiration.
