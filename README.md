# Proxy Verifier

Proxy Verifier is an HTTP replay tool designed to verify the behavior of HTTP
proxies. It builds a verifier-client binary and a verifier-server binary which
each read a set of YAML or JSON files that specify the HTTP traffic for the two
to exchange.

Proxy Verifier supports the HTTP replay of the following protocols:

* Replay of HTTP and HTTPS traffic.
* Replay of HTTP/1.x traffic by both the client and the server.
* Replay of client-side HTTP/2 traffic.

## Field Verification
In addition to replaying HTTP traffic, Proxy Verifier implements proxy traffic
verification via field verification rules specified in the YAML traffic files.
Each header field specification can verify one of the following:

1. The absence of a field with the specified name.
1. The presence of a field with the specified name.
1. Both the presence of a field with the specified name and value (matched case sensitively).
1. The presence of a field with the specified name with a value containing the specified value (matched case sensitively).
1. The presence of a field with the specified name with a value prefixed with the specified value (matched case sensitively).
1. The presence of a field with the specified name with a value suffixed with the specified value (matched case sensitively).

Thus the following JSON field specification requests no field verification:

```YAML
  - [ X-Forwarded-For, 10.10.10.2 ]
```

The following specifies that the HTTP field `X-Forwarded-For` _with any value_ should not have been sent by the proxy:

```YAML
  - [ X-Forwarded-For, 10.10.10.2, absent ]
```

The following specifies that the HTTP field `X-Forwarded-For` _with any value_ should  have been sent by the proxy:

```YAML
  - [ X-Forwarded-For, 10.10.10.2, present ]
```

The following specifies that `X-Forwarded-For` should have been received from the proxy with the exact value "10.10.10.2":

```YAML
  - [ X-Forwarded-For, 10.10.10.2, equal ]
```

The following specifies that `X-Forwarded-For` should have been received from the proxy containing the value "10" at any position in the actual value:

```YAML
  - [ X-Forwarded-For, 10, contains ]
```

The following specifies that `X-Forwarded-For` should have been received from the proxy with an actual value prefixed with "1":

```YAML
  - [ X-Forwarded-For, 1, prefix ]
```

The following specifies that `X-Forwarded-For` should have been received from the proxy with an actual value suffixed with "2":

```YAML
  - [ X-Forwarded-For, 2, suffix ]
```

## URL Verification

Similarly to Field Verification, a mechanism exists to verify the parts of URLs being received from the proxy by the server. The parts follow the URI specification, with scheme, host, port, authority (also known as net-loc, the combination of host and port), path, query, and fragment supported. In each of these cases, supporting characters like slashes, colons, question marks, and number signs are removed, with the exception of a URL with no scheme or authority, where a leading slash to start the path, if present, is maintained.

 The following specifies the verification of the URL `http://example.one:8080/path?query=q#Frag`. All rules specified in Field Verification are still supported:

```YAML
  - [ scheme, http, equal ]
  - [ host, example.one, equal ]
  - [ port, 8080, equal ]
  - [ path, path, equal ]
  - [ query, query=q, equal ]
  - [ fragment, Frag, equal ]
```

Alternatively, authority, with an alias of net-loc, could be used. It is the combination of host and port:

```YAML
  - [ authority, example.one:8080, equal ]
```

Verification of the path `/path/x/y?query=q#Frag` could be specified like this:

```YAML
  - [ authority, foo, absent ]
  - [ path, /path/x/y, equal ]
  - [ query, query=q, equal ]
  - [ fragment, foo, present ]
```

## Install

These instructions will get you a copy of the project up and running on your
local machine for development and testing purposes.


### Prerequisites

Building and running Proxy Verifier requires the following to be installed on the system:

* SCons. Proxy Verifier is built using the [SCons](https://scons.org) build tool.
* OpenSSL
* [Nghttp2](https://nghttp2.org)

### Building

OpenSSL and Nghttp2 are linked against dynamically and have their own SCons arguments to point to their locations.

```
pipenv shell
pipenv install scons scons-parts
scons -j8 --with-ssl=/path/to/openssl --with-nghttp2=/path/to/nghttp2 --cfg=release proxy-verifier
```

This will build `verifier-client` `verifier-server` in the `bin/` directory at the root of the repository.

### Running the Tests

#### Unit Tests

To build and run the unit tests, use the `run_utest` Scons target (this assumes
you are in the pipenv shell you used to build Proxy Verifier, see above):

```
scons -j8 --with-ssl=/path/to/openssl --with-nghttp2=/path/to/nghttp2 --cfg=release run_utest::
```

#### Gold Tests
Proxy Verifier ships with a set of automated end to end tests written using the
[AuTest](https://bitbucket.org/autestsuite/reusable-gold-testing-system/src/master/)
framework. To run them, simply run the `autest.sh` script:

```
cd test/autests
./autest.sh
```

This sets up the pipenv shell each time which takes a few seconds. When
developing, after the first `autest.sh` run, things can be expedited by
entering the shell and running the tests from in that shell:

```
cd test autests
pipenv shell
autest -D gold_tests
```

The `-f` option can be used to run a particular test:
```
# Within the pipenv shell, as described above:
autest -D gold_tests -f https
```

## Usage

At a high level, Proxy Verifier is run in the following manner:

1. Run the verifier-server with the set of HTTP and HTTPS ports to listen on
   configured though the command line. The directory containing the replay file
   is also configured through a command line argument.
1. Configure and run the proxy to listen on a set of HTTP and HTTPS ports and
   to proxy those connections to the listening verifier-server ports.
1. Run the verifier-client with the sets of HTTP and HTTPS ports on which to
   connect configured though the command line. The directory containing the
   replay file is also configured through a command line argument.

Here's an example invocation of the verifier-server, configuring it to listen on
localhost port 8080 for HTTP connections and localhost port 4443 for HTTPS
connections:

```
verifier-server \
    run \
    --listen 127.0.0.1:8080 \
    --listen-https 127.0.0.1:4443 \
    --server-cert <server_cert> \
    --ca-certs <file_or_directory_of_ca_certs> \
    <replay_file_directory>
```

Here's an example invocation of the verifier-client, configuring it to connect to
the proxy which has been  configured to listen on localhost port 8081 for HTTP
connections and localhost port 4444 for HTTPS connections:

```
verifier-client \
    run \
    --client-cert <client_cert> \
    --ca-certs <file_or_directory_of_ca_certs> \
    <replay_file_directory> \
    127.0.0.1:8081 \
    127.0.0.1:4444
```

With these two invocations, the verifier-client and verifier-server will replay the
sessions and transactions in `<replay_file_directory>`  and perform any field
verification described therein.

Note that the `--client-cert` and `--server-cert` both take either a
certificate file containing the public and private key or a directory
containing pem and key files. Similarly, the `--ca-certs` takes either a file
containing one or more certificates or a directory with separate certificate
files.  For convenience, the `test/keys` directory contains key files which can
be used for testing.

### Optional Arguments

#### --format \<format-specification\>

Each transaction has to be uniquely identifiable by the client and server in a
way that is consistent across both replay file parsing and traffic replay
processing.  Whatever attributes we use from the messages to uniquely identify
transactions is called the "key" for the dataset. The ability to uniquely
identify these messages is important for at least the following reasons:

* When the Verifier server receives a request, it has to know from which of the
  set of parsed transactions it should generate a response. At the time of
  processing an incoming message, all it has to go on is the request header
  line and the request header fields. From these, it has to be able to identify
  which of the potentially thousands of parsed transactions from the replay input
  files it should generate a response.
* When the client and server perform field verification, they need to know what
  particular verification rules specified in the replay files should be applied
  to the given incoming message.
* If the client and server are processing many transactions, generic log
  messages could be near useless if there was not a way for the logs to
  identify individual transactions to the user somehow.

By default the Verifier client and server both expect a `uuid` header field
value to function as the key.

If the user would like to use other attributes as a key, they can specify
something else via the `--format` argument. The format argument currently
supports generating a key on arbitrary field values and the `URL` of the
request. Some example `--format` expressions include:

* `--format "{field.uuid}"`: This is the default key format. It treats the UUID
  header field value as the transaction key.
* `--format "{url}"`: Treat the request `URL` as the key.
* `--format "{field.host}"`: Treat the `Host` header field value as the key.
* `--format "{field.host}/{url}"`: Treat the combination of the `Host` header
  field and the request `URL` as the key.

#### --keys \<key1 key2 ... keyn\>

`--keys` can be passed to the verifier-client to specify a subset of keys from
the replay file to run. Only the transactions from the space-separated list of
keys will be replayed. For example, the following invocation will only run the
transactions with keys whose values are 3 and 5:

```
verifier-client \
    run \
    <replay_file_diretory> \
    127.0.0.1:8082 \
    127.0.0.1:4443 \
    --keys 3 5
```

This is a client-side only option.

#### --verbose

Proxy Verifier has four levels of verbosity that it can run with:

| Verbosity | Description |
| --------- | ----------- |
| error     | Transactions either failed to run or failed verification. |
| warning   | A non-failing problem occurred but something is likely to go wrong in the future. |
| info      | High level test execution information. |
| diag      | Low level debug information. |


Each level implies the ones above it. Thus, if a user specifies a verbosity
level of `warning`, then both warning and error messages are reported.

By default, Proxy Verifier runs at `info` verbosity, only producing summary
output by both the client and the server along with any warnings and errors it
found. This can be tweaked via the `--verbose` flag. Here's an example of requesting
the most verbose level of logging (`diag`):

```
verifier-client \
    run \
    <replay_file_diretory> \
    127.0.0.1:8082 \
    127.0.0.1:4443 \
    --verbose diag
```

#### --no-proxy

As explained above, replay files contain traffic information for both client to
proxy traffic and proxy to server traffic.  Under certain circumstances it may
be helpful to run the Verifier client directly against the Verifier server.
This can be useful while developing Proxy Verifier itself, for example,
allowing the developer to do some limited testing without requiring the setup
of a test proxy.

To support this, the Verifier client has the `--no-proxy` option. If this
option is used, then the client has its expectations configured such that it
assumes it is run against the Verifier server rather than a proxy. Effectively
this means that instead of trying to run the client to proxy traffic, it will
instead act as the proxy host for the Verifier server and will run the proxy to
server traffic. Concretely, this means that the Verifier client will replay the
`proxy-request` and `proxy-response` nodes rather than the `client-request` and
`client-response` nodes.

This is a client-side only option.

#### --strict

Generally, very little about the replayed traffic is verified except what is
explicitly specified via field verification (see above). This is by design,
allowing the user to replay traffic with only the requested content being
verified. In high-volume cases, such as situations where Proxy Verifier is
being used to scale test the proxy, traffic verification may be considered
unimportant or even unnecessarily noisy. If, however, the user wants every
field to be verified regardless of specification, then the `--strict` option
can be passed to either or both the Proxy Verifier client and server to report
any verification issues against every field specified in the replay file.

#### --rate \<requests/second\>

By default, the client will replay the transactions in the replay file as fast
as possible. If the user desires to configure the client to replay the
transactions at a particular rate, they can provide the `--rate` argument. The
argument takes the number of requests per second the client will attempt to
send requests at.

This is a client-side only option.

#### --repeat \<number\>

By default, the client will replay all the transactions once in the set of
input replay files. If the user would like the client to automatically repeat
this set a number of times, they can provide the `--repeat` argument. The
argument takes the number of times the client should replay the entire dataset.

This is a client-side only option.

## Contribute

Please refer to [CONTRIBUTING](CONTRIBUTING.md) for information about how to get involved. We welcome issues, questions, and pull requests.

## License

This project is licensed under the terms of the Apache 2.0 open source license.
Please refer to [LICENSE](LICENSE) for the full terms.
