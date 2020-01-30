..  Copyright 2020, Verizon Media
    SPDX-License-Identifier: Apache-2.0

.. include:: common-defs.rst

.. _preface:

Preface
*******

This code carries the ASF copyright. It is not, however, officially affiliated with the ASF.

This project is intended for testing of Apache Traffic Server. This is done by using a mock client
and server, and providing information to both of them by way of replay files. Once ATS is configured
in a way such that it will forward responses to the "replay server", the client can send requests,
which are configured with a list of fields to be sent in an HTTP header, a body of an arbitrary size,
and other options such as the scheme, version (of HTTP), and so on. These requests are known as
"client requests". What ATS forwards to the server, known as the "proxy requests", is identified
(using a uuid) with a "server response", which is sent (if found), and rules for that proxy request,
which are verified (any errors are reported in verbose mode). ATS forwards a "proxy response" to the
client, which can then verify that response in the same way that the server validated the proxy
request. Additionally, fields (for the client request and server response) and rules (for the proxy
request and response) can be assigned globally, using the global-field-rules node.

The motivating use case envisions certain traffic related to a known bug being recorded, converted into
a replay file with associated rules for the proxy requests and replies, and detection of any violation
of those rules, followed by further narrowing down of the replay file to isolate the bug.

Typographic Conventions
=======================

This documentation uses the following typographic conventions:

Monospace
    Represents C/C++ language statements, commands, file paths, file content,
    and computer output.

    Example:
        The test path is ``json/2819.json``.

Bracketed Monospace
    Represents variables for which you should substitute a value in file content
    or commands.

    Example:
        Use ``python3 scripts/replay_generator.py <number>`` to generate a replay file for issue 2819.

Ellipsis
    Indicates the omission of irrelevant or unimportant information.

Other Resources
===============

Websites
--------

Apache Traffic Server
    https://trafficserver.apache.org/
