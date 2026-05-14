---
name: writing-autests
description: "Create and modify Proxy Verifier AuTests (end-to-end replay tests). Use when writing new e2e test cases, adding replay YAML scenarios for HTTP/HTTPS/HTTP2/HTTP3 verification, updating .test.py files, or configuring gold file comparisons."
---

# Write Proxy Verifier AuTests

AuTest is the end-to-end testing framework for Proxy Verifier. Documentation: https://autestsuite.bitbucket.io/

## Directory Structure

Each test lives in its own subdirectory under `tests/autests/gold_tests/`:

```
tests/autests/gold_tests/<test-name>/
├── <test-name>.test.py
├── replay_files/
│   └── single_transaction.yaml
└── gold/
    ├── <name>_client.gold
    ├── <name>_server.gold
    └── <name>_proxy.gold
```

Proxy Verifier extensions are in `tests/autests/gold_tests/autest-site/`.

## Workflow

1. Create a subdirectory under `tests/autests/gold_tests/` named for the test.
2. Write a `.test.py` file with the required file prologue (see example below).
3. Create replay YAML files under `replay_files/`.
4. Add gold files under `gold/` by running the test once to capture output, or write expected output manually.
5. Run the test with `./build/dev-external/autest.sh -f <test-name>` (see `../run-autests/SKILL.md`).
6. Verify output matches gold files and no `Violation:` errors appear.

## Minimal Test Example

```python
'''
Verify <brief description>.
'''
# @file
#
# Copyright 2025, Yahoo Inc.
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify <brief description>.
'''

r = Test.AddTestRun("Description of this test run")
client = r.AddClientProcess("client1", "replay_files/my_replay.yaml")
server = r.AddServerProcess("server1", "replay_files/my_replay.yaml")
proxy = r.AddProxyProcess("proxy1",
                          listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout = "gold/my_replay_client.gold"
server.Streams.stdout = "gold/my_replay_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:", "There should be no verification errors.")
server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:", "There should be no verification errors.")
```

For HTTPS, pass `use_ssl=True` to `AddProxyProcess` and use `Variables.https_port`.

## Replay YAML Structure

```yaml
---
meta:
  version: '1.0'

sessions:
- protocol:
    stack: http
  transactions:
  - client-request:
      version: '1.1'
      method: GET
      url: /path
      headers:
        encoding: esc_json
        fields:
        - [ Host, example.com ]
        - [ uuid, 1 ]
    server-response:
      status: 200
      reason: OK
      headers:
        encoding: esc_json
        fields:
        - [ Content-Length, '0' ]
```

For HTTPS sessions, use `stack: https` with a `tls: { sni: <hostname> }` block.

## Key Extension APIs

Available in `.test.py` via extensions in `autest-site/`:

- `r.AddClientProcess(name, replay_dir, configure_http=True, configure_https=True, use_ipv6=False, other_args='')` — verifier-client process
- `r.AddServerProcess(name, replay_dir, configure_http=True, configure_https=True, other_args='')` — verifier-server process
- `r.AddProxyProcess(name, listen_port, server_port, use_ssl=False)` — test proxy process
- `Testers.ContainsExpression(expr, reason)` — assert output contains a pattern
- `Testers.ExcludesExpression(expr, reason)` — assert output does not contain a pattern
