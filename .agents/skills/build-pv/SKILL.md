---
name: build-pv
description: Format and build Proxy Verifier.
---

# Build Proxy Verifier

Proxy Verifier is built with CMake and the checked-in presets. The main build
choices are:

- `dev`: debug development build.
- `dev-asan`: debug development build with AddressSanitizer.
- `portable`: portable release build with static third-party dependencies.
- `native`: host-tuned dynamic release build.

## Dependencies

OpenSSL 3.5 or newer, nghttp2, and nghttp3 must be installed through the system
package manager. Use one of the development Dockerfiles when the host does not
provide these dependencies.

## macOS notes

On macOS, prefer Apple clang over a Homebrew LLVM `clang` if the latter appears
earlier in `PATH`:

```bash
export CC="$(xcrun -find clang)"
export CXX="$(xcrun -find clang++)"
export SDKROOT="$(xcrun --show-sdk-path)"
```

## Build commands

```bash
cmake --preset dev
cmake --build --preset dev --parallel
```

Run the formatter before handing off code changes:

```bash
tools/format.sh
```

On macOS, keep the `CC`, `CXX`, and `SDKROOT` exports above in the environment
for the CMake configure and build as well.
