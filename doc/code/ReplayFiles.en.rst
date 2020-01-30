..  Copyright 2020, Verizon Media
    SPDX-License-Identifier: Apache-2.0

.. include:: ../common-defs.rst
.. highlight:: cpp
.. default-domain:: cpp

.. _ReplayFiles:

************
Replay Files
************

Synopsis
********

Replay files are the input files for the HttpReplay system. They consist of JSON with certain global
properties, as well as a list of sessions, which contain more properties that apply to transactions
listed within each session. Each transaction contains a client request, which represents the request
sent from the client to an Apache Traffic Server instance, the proxy request, representing the
request from the instance to the server, the server response, representing the response from the
server to the ATS instance, and the proxy response, representing the response from the instance to
the client.

The fields of the client request and server response are set beforehand by the maker of the replay
file. The client sends each request in finds in the file, while the server looks up the associated
response for each incoming proxy request and replies with the given fields, and an arbitrary body
of a specified length. The Apache Traffic Server generates the proxy request and response, so
instead of specifying fields, rules for fields are instead specified, which the client or server
will then verify upon receiving a request or response.

Supported rules for fields include equality (checking the value of a certain named field is equal
to a certain string), presence (checking a named field exists at all), and absence (checking a named
field does not exist). Rules for fields can also be applied globally, to all transactions, by
listing them in a "global field rules" list at the beginning of the replay file.

Examples
========

Here is a simple example outlining the structure of a replay file. Note the override of the "Host"
field, the arrays of length 2 in the client request and server response, and the arrays of length 3
in the proxy request and response. Note that the same uuid is present as a field in all four parts of
a transaction, making an exception to the length 3 rule in the proxy request and response. It is
optoinal for the proxy response, but required for the request.

.. literalinclude:: ../../json/doc.json

An example with YAML transclusions is below.

.. literalinclude:: ../../json/2819.yaml

A longer example is below. When intending to send a body (the HTTP server will generate one consisting
of sequential numbers), make sure to include both the Content-Length field in the list of fields in
addition to the content field (with a nested size field) at the base level of a server response node.

.. literalinclude:: ../../json/2534.yaml
