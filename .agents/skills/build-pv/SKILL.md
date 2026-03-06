---
name: build-pv
description: Format and build Proxy Verifier.
---

# Build Apache Traffic Server

Proxy Verifier is built via scons and scons-parts. One of the challenges is
that the project, in order to be built with full HTTP/2 and Quic support,
requires building a set of libraries to support these features, such
as openssl, nghttp2, and nghttp3. This skill explains how to build these
dependencies and the proxy verifier project.

## Build Dependancies

Proxy verifier dependencies are installed in: `/opt/pv_libs`. If that directory
does not exist, or if the user explicitly asks to rebuild it, then run the
following to build them:

```bash

sudo rm -rf /opt/pv_libs # If the user is asking to reinstall the libraries.

tools/build_library_dependencies.sh /opt/pv_libs
```

## Subsequent builds

Once `/opt/pv_libs` exists, the build is done via scons:

```bash

if [ "$(uname)" = "Linux" ]
then
  num_threads=$(nproc)
else
  num_threads=$(sysctl -n hw.logicalcpu)
fi
uv run scons -j${num_threads} --with-libs=/opt
```


