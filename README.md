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
1. Both the presence of a field with the specified name and value (matched cases sensitively).

Thus the following JSON field specification requests no field verification:

```YAML
  - [ X-Forwarded-For, 10.10.10.2 ]
```

The following specifies that the HTTP field `X-Forwarded-For` _with any value_ should not have been sent by the proxy:

```YAML
  - [ X-Forwarded-For, 10.10.10.2, absent ]
```

The following specifies that `X-Forwarded-For` should have been received from the proxy with the exact value "10.10.10.2":

```YAML
  - [ X-Forwarded-For, 10.10.10.2, equal ]
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
    --cert <key_and_cert_pem> \
    <replay_file_directory>
```

Here's an example invocation of the verifier-client, configuring it to connect to
the proxy which has been  configured to listen on localhost port 8081 for HTTP
connections and localhost port 4444 for HTTPS connections:

```
verifier-client \
    run \
    <replay_file_directory> \
    127.0.0.1:8081 \
    127.0.0.1:4444
```

With these two invocations, the verifier-client and verifier-server will replay the
sessions and transactions in `<replay_file_directory>`  and perform any field
verification described therein.

## Contribute

Please refer to [CONTRIBUTING](CONTRIBUTING.md) for information about how to get involved. We welcome issues, questions, and pull requests.

## License

This project is licensed under the terms of the Apache 2.0 open source license.
Please refer to [LICENSE](LICENSE) for the full terms.
