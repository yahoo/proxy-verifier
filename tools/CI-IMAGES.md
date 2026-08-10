<!--
  @file

  Copyright 2026, Verizon Media
  SPDX-License-Identifier: Apache-2.0
-->

# Proxy Verifier CI Image

Proxy Verifier CI uses Ubuntu 26.04. The image installs Ubuntu's OpenSSL,
nghttp2, and nghttp3 development packages, along with the system compiler,
CMake, Ninja, `uv`, formatting tools, and a checksum-verified Apache RAT JAR.
CI therefore builds against the same system libraries available to developers;
it does not maintain a separate dependency tree under `/opt`.

This image is for development and CI workflows, not deployment. Use the
statically linked binaries attached to Proxy Verifier releases for deployment.

## Image Tag

| Distribution | Dockerfile | Multi-platform CI tag |
| --- | --- | --- |
| Ubuntu 26.04 | `docker/ubuntu_26.04/Dockerfile` | `ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:26.04` |

The architecture-specific inputs append `-amd64` or `-arm64` to the tag. For
example, the Ubuntu inputs are `ubuntu:26.04-amd64` and
`ubuntu:26.04-arm64`.

## Prerequisites

Build from an up-to-date Proxy Verifier checkout with Docker and the Docker
Buildx plugin installed. Run every build command from the repository root.
Prefer native builders because CPU emulation is significantly slower:

* Build `linux/amd64` on an x86_64 Linux host.
* Build `linux/arm64` on an arm64 Linux host or an Apple Silicon Mac.

Confirm the platforms supported by the active builder and authenticate before
pushing:

```bash
docker buildx ls
docker login ci.trafficserver.apache.org:5000
```

The commands below disable Buildx's default provenance attestation. The CI
registry's `docker manifest create` workflow requires each architecture tag to
resolve directly to an image manifest rather than another image index.

## Build And Verify An Architecture

Choose one row from the image table and one platform. This example builds the
Ubuntu AMD64 image; substitute the Dockerfile, image name, version, platform,
and suffix for the other combinations.

```bash
dockerfile=docker/ubuntu_26.04/Dockerfile
image=ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu
version=26.04
platform=linux/amd64
suffix=amd64

docker buildx build \
  --load \
  --pull \
  --provenance=false \
  --platform "${platform}" \
  --file "${dockerfile}" \
  --tag "${image}:${version}-${suffix}" \
  --progress plain \
  .
```

Verify the image's architecture and the system dependency toolchain:

```bash
docker image inspect "${image}:${version}-${suffix}" \
  --format '{{.Os}}/{{.Architecture}}'

docker run --rm --platform "${platform}" \
  "${image}:${version}-${suffix}" bash -lc '
    set -euo pipefail
    cmake --version
    ninja --version
    uv --version
    cc --version
    c++ --version
    java -version
    test -r "${RAT_JAR}"
    java -jar "${RAT_JAR}" --help >/dev/null
    pkg-config --modversion openssl libnghttp2 libnghttp3
  '
```

The inspect command should print the requested platform. Push the verified
architecture-specific image and confirm that the remote reference is a direct
image manifest:

```bash
docker push "${image}:${version}-${suffix}"
docker manifest inspect --insecure "${image}:${version}-${suffix}"
```

Repeat this process for AMD64 and ARM64.

## Publish A Multi-platform Tag

After both architecture tags for one distribution are present, create its
multi-platform tag. Continue with the Ubuntu example variables from above:

```bash
docker manifest rm "${image}:${version}" || true

docker manifest create --insecure \
  "${image}:${version}" \
  "${image}:${version}-amd64" \
  "${image}:${version}-arm64"

docker manifest push --insecure "${image}:${version}"
docker manifest inspect --insecure "${image}:${version}"
```

Do not push if `docker manifest create` fails. A failed create can leave a
partial local manifest, so remove it before correcting the architecture tags
and retrying. The final inspection must list both `linux/amd64` and
`linux/arm64`.

The GitHub Actions workflow pulls the multi-platform Ubuntu tag without
choosing an architecture explicitly.

## Rebuilding Images

Rebuild and republish both architectures whenever
`docker/ubuntu_26.04/Dockerfile` changes.

Images should also be rebuilt periodically so `--pull` incorporates security
and bug-fix updates from each distribution. Recreate and verify the
multi-platform tag after pushing both architecture-specific images.
