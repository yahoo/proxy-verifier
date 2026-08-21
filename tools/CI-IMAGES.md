<!--
  @file

  Copyright 2026, Verizon Media
  SPDX-License-Identifier: Apache-2.0
-->

# Proxy Verifier Build Images

Proxy Verifier provides Dockerfiles for Alpine 3.24, Fedora 44, and Ubuntu
26.04 build environments. GitHub Actions uses only Ubuntu 26.04. The Alpine
and Fedora Dockerfiles are available for users who prefer those distributions
for their local build environment. Alpine is also the portable Linux release
environment. Each Dockerfile installs its distribution's OpenSSL, nghttp2,
nghttp3, and liburing development packages, along with compilers, CMake, Ninja,
`uv`, formatting tools, and a checksum-verified Apache RAT JAR. The Ubuntu
image includes both GCC and Clang for the CI test jobs.

These images are for development, release builds, and CI workflows, not
deployment. Use the statically linked binaries attached to Proxy Verifier
releases for deployment.

## Build Environments

| Distribution | Dockerfile | Usage |
| --- | --- | --- |
| Alpine 3.24 | `docker/alpine_3.24/Dockerfile` | Optional local and release build environment |
| Fedora 44 | `docker/fedora_44/Dockerfile` | Optional local build environment |
| Ubuntu 26.04 | `docker/ubuntu_26.04/Dockerfile` | Published CI and local build environment |

The Ubuntu image is built for `linux/amd64` and `linux/arm64` and published to
GitHub Container Registry by the `Publish Ubuntu CI image` workflow. The
workflow runs whenever its Dockerfile or workflow definition changes on
`master`, and it can also be started manually from GitHub Actions.

Users who prefer Alpine or Fedora can build those Dockerfiles locally. GitHub
Actions does not publish images for those environments.

## Build And Verify A Local Image

Build from an up-to-date Proxy Verifier checkout with Docker and the Docker
Buildx plugin installed. Run every build command from the repository root.
Prefer a native platform because CPU emulation is significantly slower:

* Build `linux/amd64` on an x86_64 Linux host.
* Build `linux/arm64` on an arm64 Linux host or an Apple Silicon Mac.

This example builds Alpine for AMD64. Substitute the Fedora Dockerfile and a
different local tag to use Fedora instead.

```bash
dockerfile=docker/alpine_3.24/Dockerfile
image=pv-dev:alpine3.24
platform=linux/amd64

docker buildx build \
  --load \
  --pull \
  --provenance=false \
  --platform "${platform}" \
  --file "${dockerfile}" \
  --tag "${image}" \
  --progress plain \
  .
```

Verify the image's architecture and the system dependency toolchain:

```bash
docker image inspect "${image}" \
  --format '{{.Os}}/{{.Architecture}}'

docker run --rm --platform "${platform}" \
  "${image}" bash -lc '
    set -euo pipefail
    cmake --version
    ninja --version
    uv --version
    cc --version
    c++ --version
    java -version
    test -r "${RAT_JAR}"
    java -jar "${RAT_JAR}" --help >/dev/null
    pkg-config --modversion openssl libnghttp2 libnghttp3 liburing
  '
```

## Rebuilding Images

Rebuild a local Alpine or Fedora image whenever its Dockerfile changes or when
you want current distribution packages. The `--pull` option refreshes the base
image, while `--no-cache` can be added to refresh every installed package.

The `Publish Ubuntu CI image` workflow rebuilds and publishes the Ubuntu
image automatically when `docker/ubuntu_26.04/Dockerfile` changes. Run the
workflow manually to refresh its base image and installed packages without a
Dockerfile change.
