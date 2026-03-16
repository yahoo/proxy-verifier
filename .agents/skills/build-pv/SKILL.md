---
name: build-pv
description: Format and build Proxy Verifier.
---

# Build Proxy Verifier

Proxy Verifier is built with CMake and the checked-in presets. The main build
choices are:

- `dev-external`: use a prebuilt dependency tree such as `/opt/pv_libs`.
- `dev-bootstrap`: let CMake fetch and build the QUIC/TLS dependencies.
- `dev-external-asan`: ASan build with a prebuilt dependency tree.
- `dev-bootstrap-asan`: ASan build with CMake-managed dependencies.
- `portable-external`: portable release build using `/opt/pv_libs`.
- `portable-bootstrap`: portable release build with CMake-managed dependencies.
- `native-external`: host-tuned dynamic build using `/opt/pv_libs`.
- `native-bootstrap`: host-tuned dynamic build with CMake-managed dependencies.

## Dependency build

Proxy verifier can still use an external dependency tree in `/opt/pv_libs`. If
that directory does not exist, or if the user explicitly asks to rebuild it,
run the following:

```bash
sudo rm -rf /opt/pv_libs # If the user is asking to reinstall the libraries.
tools/build-library-dependencies.sh /opt/pv_libs
```

## macOS notes

On macOS, prefer Apple clang over a Homebrew LLVM `clang` if the latter appears
earlier in `PATH`:

```bash
export CC="$(xcrun -find clang)"
export CXX="$(xcrun -find clang++)"
export SDKROOT="$(xcrun --show-sdk-path)"
```

The dependency script expects a sane autotools install and will fail fast if
`autoreconf`, `autoconf`, or `automake` are not runnable. If that happens, fix
the local environment instead of working around it in the script. On macOS, the
first repair step should be:

```bash
brew reinstall perl autoconf automake
```

## Build commands

For an external dependency tree where the dependencies live in /opt/pv_libs:

```bash
cmake --preset dev-external
cmake --build --preset dev-external --parallel
```

For CMake-managed dependency bootstrap:

```bash
cmake --preset dev-bootstrap
cmake --build --preset dev-bootstrap --parallel
```

On macOS, keep the `CC`, `CXX`, and `SDKROOT` exports above in the environment
for the CMake configure and build as well.
