---
name: create-release
description: Cut a Proxy Verifier release - pick the semantic version, merge a version-bump prep PR, push an annotated tag, build and test stripped static verifier-client / verifier-server binaries for darwin-arm64, linux-arm64, and linux-amd64, publish the GitHub release with the tarball, and mirror it to the controller bintray directory. Use when asked to do, cut, or publish a Proxy Verifier release.
---

# Create A Proxy Verifier Release

A release is an annotated `vX.Y.Z` tag on `yahoo/proxy-verifier` master, a
GitHub release carrying `proxy-verifier-vX.Y.Z.tar.gz`, and a copy of that
tarball in `/home/docs/bintray` on the CI controller. The tarball holds
stripped, statically linked binaries so users can drop them in without
installing any libraries.

## Inputs

Settle these before starting. Ask the user for any you cannot infer.

- `UPSTREAM`: git remote for `yahoo/proxy-verifier` (usually `upstream`;
  `origin` is usually the releaser's fork). Check `git remote -v`.
- `VERSION`: the new version without the `v`, chosen in step 1. Confirm it
  with the user before opening the prep PR.
- `AMD64_HOST`: ssh destination for a native x86_64 Linux host with `docker`
  or `podman`. Ask the user for one; do not assume. Confirm `uname -m`
  prints `x86_64` before building there.
- `CONTROLLER`: ssh destination for the CI controller (default ssh alias
  `controller`). It has passwordless sudo.
- `RELEASER`: name for the tag header, the releaser's email local part
  (for example `brian.neradt`).

This assumes an arm64 Mac host with Docker (or Rancher Desktop), `gtar`
(`brew install gnu-tar`), and `gh` authenticated as an account that can
merge to and release on `yahoo/proxy-verifier`.

Hosts behind YubiKey-protected jump hosts need a touch for each new ssh
master connection. Tell the user before each connection that may prompt. A
`Permission denied (publickey)` from the jump host usually means the user's
SSH certificate has expired; ask them to refresh it and retry.

Use a scratch directory, here `S`, for the source archive, staged binaries,
and notes.

## 1. Choose The Version

```bash
git fetch UPSTREAM --tags
last=$(git describe --tags --abbrev=0 UPSTREAM/master)
git log --format='%h %s' "${last}..UPSTREAM/master"
git diff "${last}" UPSTREAM/master -- README.md
```

Follow semantic versioning strictly; do not default to a patch bump:

- **Major** (`X+1.0.0`): users must change replay/YAML files or how they invoke
  the binaries.
- **Minor** (`X.Y+1.0`): new user-facing features, such as a new CLI option, a
  new replay/YAML key, or new verification behavior.
- **Patch** (`X.Y.Z+1`): only bug fixes, performance, build, test, CI, docs, or
  tooling changes.

Read the commit bodies and the README diff to classify each change, then
propose the version with a one-line justification for the user to confirm.

## 2. Prep PR

Bump the `project(... VERSION ...)` line in `CMakeLists.txt`, the only place
the version lives. `--version` output and the install prefix
`/tmp/proxy-verifier-vX.Y.Z` derive from it.

```bash
git switch -c vVERSION-prep UPSTREAM/master
sed -i '' "s/^  VERSION ${last#v}\$/  VERSION VERSION/" CMakeLists.txt
git diff
git commit -am "vVERSION release prep"
git push -u origin vVERSION-prep
gh pr create -R yahoo/proxy-verifier --base master \
  --head FORK_OWNER:vVERSION-prep --title "vVERSION release prep" \
  --assignee @me --body "Bump the project version to VERSION."
```

The PR body must also carry the repository's license-confirmation line:

```text
I confirm that this contribution is made under the terms of the license found in the root directory of this repository's source tree and that I have the authority necessary to make this contribution on behalf of its copyright owner.
```

The step 3 builds can start now from the prep branch while CI runs: a squash
merge of this single commit on top of an unchanged master produces an
identical tree, and step 4 verifies that. When CI is green, squash-merge the
PR if the user approved doing so; otherwise wait for them to merge it.

## 3. Build And Test Each Platform

Run the three platforms in parallel. Each one uses
`tools/build-portable-binaries`, which configures the `portable` preset,
builds, and runs `cmake --install --strip`. It installs to
`/tmp/proxy-verifier-vVERSION/<target>/verifier-{client,server}`. Then run
the unit and Uranium tests against that build. All three must pass:

```bash
bash tools/build-portable-binaries
ctest --preset portable
./build/portable/urtest.sh -n 8
```

Ship exactly the committed tree to the Linux builders with `git archive`;
the release tag may not exist yet, so do not clone from GitHub:

```bash
git archive --prefix=proxy-verifier/ -o "$S/pv-src.tar" vVERSION-prep
```

### darwin-arm64 (local Mac)

Run the commands above from a clean checkout of the prep branch at the repo
root.

### linux-arm64 (local container)

The Alpine image provides musl plus the static archives (OpenSSL, nghttp2,
nghttp3, liburing, jemalloc) that the static link needs. `--privileged` lets
the io_uring tests run.

```bash
(cd docker/alpine_3.24 && docker build -t pv-release .)
docker run -d --name pvrelease --privileged pv-release sleep infinity
docker cp "$S/pv-src.tar" pvrelease:/root/
docker exec pvrelease bash -lc 'cd /root && tar xf pv-src.tar && cd proxy-verifier &&
  bash tools/build-portable-binaries && ctest --preset portable &&
  ./build/portable/urtest.sh -n 8'
```

### linux-amd64 (AMD64_HOST)

Use the same Alpine container on the remote host, not the host's own
toolchain. The host distribution usually lacks the static archives, and
using the container keeps both Linux builds identical.

```bash
D='~/pv-release-vVERSION'
ssh AMD64_HOST "mkdir -p $D && uname -m"
scp "$S/pv-src.tar" AMD64_HOST:pv-release-vVERSION/
ssh AMD64_HOST "cd $D && tar xf pv-src.tar &&
  cd proxy-verifier/docker/alpine_3.24 && docker build -t pv-release . &&
  docker run -d --name pvrelease --privileged pv-release sleep infinity &&
  docker cp $D/pv-src.tar pvrelease:/root/ &&
  docker exec pvrelease bash -lc 'cd /root && tar xf pv-src.tar && cd proxy-verifier &&
    bash tools/build-portable-binaries && ctest --preset portable &&
    ./build/portable/urtest.sh -n 16'"
```

## 4. Tag

Confirm that the merged commit has the tree that was built and tested:

```bash
git fetch UPSTREAM
test "$(git rev-parse UPSTREAM/master^{tree})" = "$(git rev-parse vVERSION-prep^{tree})"
```

If the trees differ, for example because master moved, rebuild from the
merged commit. Then create the annotated tag on the prep merge commit. The
message is a header line followed by one line per commit since the last
release, excluding the prep commit itself:

```bash
prep=$(git rev-parse UPSTREAM/master)
{ echo "Version vVERSION ($(date +%m/%d/%Y), RELEASER)"; echo
  git log --no-merges --format='* %ae %s' "${last}..${prep}^" |
    sed -E 's/^\* ([^@]+)@[^ ]+ /* \1 /'; } > "$S/tag-msg.txt"
git tag -a vVERSION -F "$S/tag-msg.txt" "$prep"
git push UPSTREAM vVERSION
git ls-remote --tags UPSTREAM 'vVERSION^{}'   # must print $prep
```

The result looks like:

```text
Version v3.2.1 (10/14/2026, brian.neradt)

* brian.neradt Speed up replay parsing with more threads and jemalloc (#407)
* brian.neradt Honor --rate for replays without session timestamps (#405)
```

## 5. Stage And Verify The Binaries

```bash
R="$S/release/proxy-verifier-vVERSION"
mkdir -p "$R"/{darwin-arm64,linux-arm64,linux-amd64}
cp /tmp/proxy-verifier-vVERSION/darwin-arm64/verifier-* "$R/darwin-arm64/"
docker cp pvrelease:/tmp/proxy-verifier-vVERSION/linux-arm64/verifier-client "$R/linux-arm64/"
docker cp pvrelease:/tmp/proxy-verifier-vVERSION/linux-arm64/verifier-server "$R/linux-arm64/"
ssh AMD64_HOST "cd $D && mkdir -p out &&
  docker cp pvrelease:/tmp/proxy-verifier-vVERSION/linux-amd64/verifier-client out/ &&
  docker cp pvrelease:/tmp/proxy-verifier-vVERSION/linux-amd64/verifier-server out/"
scp "AMD64_HOST:pv-release-vVERSION/out/verifier-*" "$R/linux-amd64/"
(cd "$S/release" && find proxy-verifier-vVERSION | sort)
```

Verify each binary at its original location (inside each container, and on
the Mac):

- **cksum**: `cksum` at the original location must match `cksum` of the
  staged copy.
- **Linux static**: `file` must report `static-pie linked, stripped`, and
  `readelf -d BIN | grep -c NEEDED` must print `0`. musl's `ldd` lists
  `/lib/ld-musl-*.so.1` even for static-pie binaries, so do not rely on `ldd`
  output alone.
- **macOS**: `otool -L` must list only `/usr/lib/libc++.1.dylib` and
  `/usr/lib/libSystem.B.dylib`. A stripped Mach-O executable keeps only
  external (uppercase) symbols in `nm`.
- **Version**: `verifier-client --version` prints `Version VERSION of Proxy
  Verifier`.

## 6. Create The Tarball And GitHub Release

Use GNU tar: macOS `tar` adds extended attributes that make Linux `tar` warn.

```bash
(cd "$S/release" && gtar czf proxy-verifier-vVERSION.tar.gz proxy-verifier-vVERSION &&
  gtar tvzf proxy-verifier-vVERSION.tar.gz && shasum proxy-verifier-vVERSION.tar.gz)
```

Write a concise title and Markdown notes from the commits since the last
release. Group them under headings such as `New features`, `Performance`,
`Bug fixes`, and `Build and tooling`, with PR numbers. Earlier releases'
notes (`gh release view vX.Y.Z -R yahoo/proxy-verifier`) show the style. Then
publish:

```bash
gh release create vVERSION -R yahoo/proxy-verifier --verify-tag \
  --title "TITLE" --notes-file "$S/notes.md" \
  "$S/release/proxy-verifier-vVERSION.tar.gz"
gh release view vVERSION -R yahoo/proxy-verifier --json tagName,isDraft,assets
gh release list -R yahoo/proxy-verifier -L 2
```

Confirm that the release is not a draft, is marked `Latest`, and has the one
`.tar.gz` asset. Its `sha256:` digest must equal `shasum -a 256` of the local
tarball.

## 7. Mirror To The Controller Bintray

```bash
ssh CONTROLLER 'set -e; version=vVERSION; cd /home/docs/bintray
  test ! -e proxy-verifier-${version}.tar.gz
  sudo wget -q https://github.com/yahoo/proxy-verifier/releases/download/${version}/proxy-verifier-${version}.tar.gz
  sha1sum proxy-verifier-${version}.tar.gz; ls -la proxy-verifier-${version}.tar.gz'
shasum "$S/release/proxy-verifier-vVERSION.tar.gz"
```

The two sha1 values must match, and the file must be `-rw-r--r-- root root`.

## 8. Clean Up And Report

Remove the containers and remote scratch tree:

```bash
docker rm -f pvrelease
ssh AMD64_HOST "docker rm -f pvrelease && rm -rf $D"
```

Report to the user: the version and why, the prep PR, the tag commit, the
test results for each platform, the release URL, and the tarball sha1 for
both local and bintray.
