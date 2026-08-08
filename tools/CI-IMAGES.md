<!--
  @file

  Copyright 2026, Verizon Media
  SPDX-License-Identifier: Apache-2.0
-->

# Proxy Verifier CI Images

The Ubuntu CI image provides the Proxy Verifier build and AuTest toolchain plus
prebuilt OpenSSL, nghttp2, and nghttp3 libraries under `/opt/pv_libs`. CI can
therefore use the `dev-external` CMake preset without rebuilding those
dependencies for every pull request.

These images are for development and CI workflows, not deployment. Use the
statically linked binaries attached to Proxy Verifier releases for deployment.

## Image Tags

The CI registry uses architecture-specific tags as inputs to a multi-platform
tag:

| Image | Platform |
| --- | --- |
| `ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-amd64` | `linux/amd64` |
| `ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-arm64` | `linux/arm64` |
| `ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04` | Multi-platform image |

Docker selects the matching architecture automatically when CI pulls the
multi-platform `24.04` tag.

## Prerequisites

Build from an up-to-date Proxy Verifier checkout with Docker and the Docker
Buildx plugin installed. Run every build command from the repository root. The
Dockerfile copies `tools/build-library-dependencies.sh` from the build context,
so using `docker/ubuntu_24.04` as the context will not work.

Prefer native builders because compiling OpenSSL and the nghttp libraries under
CPU emulation is significantly slower:

* Build `linux/amd64` on an x86_64 Linux host.
* Build `linux/arm64` on an arm64 Linux host or an Apple Silicon Mac.

The build commands disable Buildx's default provenance attestation. A
provenance attestation wraps a single-platform image and its attestation in an
OCI image index. The `docker manifest create` command used with the CI registry
cannot use that image index as a constituent of another index; it requires each
architecture-specific tag to resolve directly to an image manifest.

Confirm the platforms supported by the active builder with:

```bash
docker buildx ls
```

Authenticate before pushing if the Docker client is not already logged in:

```bash
docker login ci.trafficserver.apache.org:5000
```

## Build And Push The AMD64 Image

On an x86_64 host, run:

```bash
docker buildx build \
  --load \
  --pull \
  --provenance=false \
  --platform linux/amd64 \
  --target dev-external \
  --file docker/ubuntu_24.04/Dockerfile \
  --tag ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-amd64 \
  --progress plain \
  .
```

Verify the image before pushing it:

```bash
docker image inspect \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-amd64 \
  --format '{{.Os}}/{{.Architecture}}'

docker run --rm --platform linux/amd64 \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-amd64 \
  bash -lc '
    set -euo pipefail
    uname -m
    cmake --version
    ninja --version
    uv --version
    /opt/pv_libs/openssl/bin/openssl version
    find /opt/pv_libs -mindepth 1 -maxdepth 1 -type d -printf "%f\n" | sort
  '
```

The inspect command should print `linux/amd64`. Push the verified image:

```bash
docker push \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-amd64

docker manifest inspect --insecure \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-amd64
```

The remote manifest must be a direct image manifest, such as
`application/vnd.oci.image.manifest.v1+json`, rather than an OCI image index or
Docker manifest list. Rebuild with `--provenance=false` before continuing if
the inspection reports an index or list.

## Build And Push The ARM64 Image

On an Apple Silicon Mac or arm64 Linux host, run:

```bash
docker buildx build \
  --load \
  --pull \
  --provenance=false \
  --platform linux/arm64 \
  --target dev-external \
  --file docker/ubuntu_24.04/Dockerfile \
  --tag ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-arm64 \
  --progress plain \
  .
```

Verify the image before pushing it:

```bash
docker image inspect \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-arm64 \
  --format '{{.Os}}/{{.Architecture}}'

docker run --rm --platform linux/arm64 \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-arm64 \
  bash -lc '
    set -euo pipefail
    uname -m
    cmake --version
    ninja --version
    uv --version
    /opt/pv_libs/openssl/bin/openssl version
    find /opt/pv_libs -mindepth 1 -maxdepth 1 -type d -printf "%f\n" | sort
  '
```

The inspect command should print `linux/arm64`. `uname -m` inside the
container normally prints `aarch64`. Push the verified image:

```bash
docker push \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-arm64

docker manifest inspect --insecure \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-arm64
```

As with the amd64 image, the remote manifest must be a direct image manifest,
not an OCI image index or Docker manifest list.

## Publish The Multi-Platform Tag

Both architecture-specific images must be present in the registry before the
multi-platform tag can be created. The manifest can be published from either
build host. `docker manifest create` reads the architecture-specific manifests
directly from the registry, so pulling the images first is unnecessary. In
particular, pulling the arm64 tag on an amd64 host without an explicit
`--platform linux/arm64` fails because Docker looks for an amd64 image under
that tag.

Remove any existing local definition of the multi-platform manifest. This
command does not remove the manifest from the registry. Skip it if Docker
reports that the local manifest does not exist:

```bash
docker manifest rm \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04
```

Create and push the joined manifest. The CI registry requires `--insecure` for
these manifest operations:

```bash
docker manifest create --insecure \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04 \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-amd64 \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04-arm64
```

Do not run `docker manifest push` if `docker manifest create` fails. A failed
create can leave a partial local manifest containing only the sources processed
before the error. Remove that local manifest before correcting the source tags
and retrying the create command.

After a successful create, push the manifest:

```bash
docker manifest push --insecure \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04
```

Verify that the published manifest contains both platforms:

```bash
docker manifest inspect --insecure \
  ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04
```

The output should list `linux/amd64` and `linux/arm64` manifests. CI jobs can
then use `ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:24.04` without
selecting an architecture-specific tag. Pin the multi-platform image digest in
a workflow when an immutable CI environment is required.

## Rebuilding Images

Rebuild and republish both architectures when either of these files changes:

* `docker/ubuntu_24.04/Dockerfile`
* `tools/build-library-dependencies.sh`

Images should also be rebuilt periodically so `--pull` incorporates security
updates from the Ubuntu 24.04 base image. After pushing both new
architecture-specific images, recreate the multi-platform tag and verify it as
described above.
