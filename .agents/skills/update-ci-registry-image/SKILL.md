---
name: update-ci-registry-image
description: Rebuild a Proxy Verifier CI Docker image (for example ubuntu:26.04) for amd64 and arm64, push it to the ci.trafficserver.apache.org:5000 controller registry, and publish the multi-arch manifest from docker1. Use when asked to update, refresh, or republish a CI registry image.
---

# Update A CI Registry Image

The ATS CI controller (`ci.trafficserver.apache.org`) hosts a private,
insecure (plain HTTP) registry on port 5000. Proxy Verifier CI pulls
multi-arch images from it, such as
`ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:26.04`. Each image is
built once per architecture, pushed under an `-amd64` / `-arm64` tag, and then
stitched into a single manifest list on `docker1`.

## Inputs

Settle these before starting. Ask the user for any you cannot infer.

- `DISTRO_DIR`: directory under `docker/`, e.g. `ubuntu_26.04`.
- `IMAGE`: registry image without the arch suffix, e.g.
  `ci.trafficserver.apache.org:5000/proxy-verifier/ubuntu:26.04`. It is
  derived from `DISTRO_DIR` (`ubuntu_26.04` -> `ubuntu:26.04`).
- `AMD64_HOST`: an ssh destination for a native x86_64 host with `docker` or
  `podman`, or `local` when this machine is x86_64. Do not assume a
  particular host; ask the user if one is not given.
- `ARM64_HOST`: same for aarch64. On Apple silicon this is usually `local`.
- `CONTROLLER`: ssh destination for the CI controller (default ssh alias
  `controller`). The registry lives here, and `docker1` is reached through it.
- `MANIFEST_HOST`: host that assembles the manifest list (default `docker1`,
  reached as `ssh CONTROLLER ssh docker1`).

Use the Dockerfile target `dev`. Build from the committed tree the user wants
published (normally an up-to-date `master`); confirm `git rev-parse HEAD`
matches `origin/master` or ask.

Hosts behind YubiKey-protected jump hosts may need a touch for each new ssh
connection. Tell the user before each connection that may prompt.

## 1. Ship The Source To Remote Builders

Remote builders need the source tree. Send exactly the committed tree with
`git archive` rather than relying on a checkout on the remote host:

```bash
D=/tmp/$USER-pv-ci-image
ssh AMD64_HOST "rm -rf $D && mkdir -p $D"
git archive HEAD | ssh AMD64_HOST "tar -x -C $D"
```

## 2. Build Each Architecture

Run the two builds in parallel; they are independent. Always use
`--no-cache --pull` so base-image and package updates are picked up.

amd64 (shown for a remote host; run it locally from the repo root if
`AMD64_HOST` is `local`):

```bash
ssh AMD64_HOST 'cd /tmp/$USER-pv-ci-image && docker build --no-cache --pull --platform linux/amd64 --target dev --file docker/DISTRO_DIR/Dockerfile --tag IMAGE-amd64 --progress plain .'
```

arm64 on a Mac with Docker Desktop (BuildKit). `--load` puts the result into
the local image store and `--provenance=false` keeps buildx from turning the
tag into a manifest list, which would break the later `manifest create`:

```bash
docker buildx build --no-cache --load --pull --platform linux/arm64 --target dev --file docker/DISTRO_DIR/Dockerfile --tag IMAGE-arm64 --progress plain --provenance=false .
```

## 3. Open The Registry Port

Port 5000 is normally denied on the controller firewall, and every host that
talks to the registry, including `docker1`, needs it open. Open it once for
the pushes and manifest steps, and always close it again in step 6, even if a
step fails:

```bash
ssh CONTROLLER 'sudo ufw allow 5000/tcp'
```

## 4. Push Each Architecture

Push each arch tag from the host that built it:

```bash
ssh AMD64_HOST 'docker push IMAGE-amd64'
docker push IMAGE-arm64
```

The registry is plain HTTP. If the builder is Podman (`docker --version`
reports `podman`), add `--tls-verify=false` to `docker push`; otherwise it
fails with `server gave HTTP response to HTTPS client`. Docker Engine hosts
need the registry in `insecure-registries` in their daemon config.

## 5. Publish The Multi-Arch Manifest On docker1

```bash
ssh CONTROLLER ssh MANIFEST_HOST '
  docker pull --platform linux/amd64 IMAGE-amd64 &&
  docker pull --platform linux/arm64 IMAGE-arm64 &&
  { docker manifest rm IMAGE || true; } &&
  docker manifest create --insecure IMAGE IMAGE-amd64 IMAGE-arm64 &&
  docker manifest push --insecure IMAGE &&
  docker manifest rm IMAGE'
```

`docker manifest rm` only drops the local manifest-list cache, and fails
harmlessly when nothing is cached. Removing it after the push makes the
verification below read from the registry rather than the local cache.

## 6. Close The Registry Port

```bash
ssh CONTROLLER 'sudo ufw deny 5000/tcp'
ssh CONTROLLER 'sudo ufw status | grep 5000'
```

Both the IPv4 and v6 `5000/tcp` rules must read `DENY`.

## 7. Verify

Run `docker manifest inspect --insecure IMAGE` on `MANIFEST_HOST` while the
port is open: once before step 4 to record the old per-arch digests, and
again after step 5:

```bash
ssh CONTROLLER ssh MANIFEST_HOST 'docker manifest inspect --insecure IMAGE'
```

The output must list both `amd64` and `arm64` platforms. Report the old and
new digests for each architecture to the user, and confirm that port 5000 is
denied again.

Finally, remove the temporary source tree from remote builders:

```bash
ssh AMD64_HOST 'rm -rf /tmp/$USER-pv-ci-image'
```
