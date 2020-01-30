..  Copyright 2020, Verizon Media
    SPDX-License-Identifier: Apache-2.0

.. include:: ../common-defs.rst
.. highlight:: text
.. default-domain:: cpp

.. _EnvironmentSetup:

*****************
Environment Setup
*****************

The environment used during testing consisted of one replay client, one replay server, one ATS
instance, and one μDNS instance.

The first item is to select a set of ports that will be used in the testing. These are

``<dns-port>``
   The port on which μDNS will server DNS queries.

``<proxy-port>``
   The port on which Traffic Server will service HTTP (plain text) requests.

``<proxy-tls-port>``
   The port on which Traffic Server will service HTTPS (TLS) and HTTP/2 requests.

``<server-port>``
   The port on which the replay server will service HTTP (plain text) requests.

``<server-tls-port>``
   The port on which the replay server will server HTTPS (TLS) and HTTP/2 requests.

All of these are shared by at least two processes and therefore need to be set consistently.

The ATS instance `SSL configuration file
<https://docs.trafficserver.apache.org/en/8.0.x/admin-guide/files/ssl_multicert.config.en.html>`__
was configured with ::

   dest_ip=* ssl_cert_name=<pem> ssl_key_name=<key>

Where ``<pem>`` and ``<key>`` refer to a public certificate and private key files that will be
shared between ATS and the replay server. The `remap configuration file
<https://docs.trafficserver.apache.org/en/8.0.x/admin-guide/files/remap.config.en.html>`__ was changed
to contain the remap rules ::

   regex_map http://(.*) http://$1:<server-port>
   regex_map https://(.*) https://$1:<server-tls-port>

This will remap requests to the proxy port to the replay server ports.

The following ATS configuration variables need to be set

`proxy.config.ssl.server.cert.path <https://docs.trafficserver.apache.org/en/9.0.x/admin-guide/files/records.config.en.html#proxy.config.ssl.server.cert.path>`__
   The path to the folder containing the ``<pem>`` file.

`proxy.config.ssl.server.private_key.path <https://docs.trafficserver.apache.org/en/9.0.x/admin-guide/files/records.config.en.html#proxy.config.ssl.server.private_key.path>`__
   The path to the folder containing the ``<key>`` file.

`proxy.config.dns.nameservers <https://docs.trafficserver.apache.org/en/9.0.x/admin-guide/files/records.config.en.html#proxy.config.dns.nameservers>`__
   The address and port for the μDNS server, generally "127.0.0.1:<dns-port>".

`proxy.config.dns.resolv_conf <https://docs.trafficserver.apache.org/en/9.0.x/admin-guide/files/records.config.en.html#proxy.config.dns.resolv_conf>`__
   Set this to the literal string "NULL" to prevent Traffic Server from using the default system DNS resolvers.

`proxy.config.http.server_ports <https://docs.trafficserver.apache.org/en/9.0.x/admin-guide/files/records.config.en.html#proxy-config-http-server-ports>`__
   Set this to "<proxy-port> <proxy-tls-port>:ssl".

μDNS was configured with the following in a ``microdnsconf.json`` file

.. code-block:: json

   {
      "mappings": [],
      "otherwise": ["127.0.0.1"]
   }

μDNS should be invoked with ::

   microdns 127.0.0.1 <dns-port> microdnsconf.json

The HTTP Replay server was invoked with ::

   replay-server run <test file> --listen 127.0.0.1:<proxy-port> --cert <combined> --listen-https 127.0.0.1:<proxy-tls-port> --verbose

Where ``<test file>`` is the JSON or YAML replay file and ``<combined>`` references a concatenated
version of the same certificate and key pair set up in records.config and ssl_multicert.config
earlier.

For both server and client, the verbose flag shows more detailed error messages, particularly with
header validation.

The HTTP Replay client was invoked with ::

   replay-client run <test file> 127.0.0.1:<proxy-port> 127.0.0.1:<proxy-tls-port> --verbose

Where ``<test file>`` is the same JSON or YAML replay file used by the server and ``<combined>``
references a concatenated version of the same certificate and key pair set up in records.config and
ssl_multicert.config earlier.

The ``key`` flag to the replay server does not refer to cryptographic keys, but instead to the
identifying flag in headers that the server uses to choose how to verify and respond to incoming
requests. It is recommended to omit it from the command line invocation (it defaults to uuid).

Example
=======

Here is a simple example outlining the structure of a replay file. Note the override of the "Host"
field, the arrays of length 2 in the client request and server response, and the arrays of length 3
in the proxy request and response.

.. literalinclude:: ../../json/doc.json
