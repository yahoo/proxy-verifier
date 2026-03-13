# Proxy Verifier Agent Notes

This repository is a C++20 codebase for HTTP replay and verification tooling.
When making changes here, prefer small, compatible edits that match the
existing project style and preserve current CLI and YAML behavior.

## First Principles

- Keep changes backwards compatible with prior released command-line argument
  usage and existing YAML replay / verification structures. Adding feautures is
  fine, but we have to support the old interface while adding new interfaces.
- Follow the local style already present in `src/core`, `src/client`,
  `src/server`, and `tests/unit_tests` rather than introducing a new house
  style per file.
- Treat user-facing behavior, replay syntax, diagnostics, and generated output
  as compatibility-sensitive.
- Update `README.md` when behavior, flags, workflows, or replay-file semantics
  change.
- For new features and bug fixes, always consider whether unit tests and AuTests
  should be added or updated. See .agents/skills/write-autests/SKILL.md for how to
  write AuTests.

## Build And Test

The common developer build uses the checked-in `dev-external` CMake preset,
which expects prebuilt QUIC / TLS dependencies under `/opt/pv_libs` unless
`PV_DEPS_ROOT` is overridden.

```bash
cmake --preset dev-external
cmake --build --preset dev-external --parallel
ctest --preset dev-external
```

For end-to-end coverage, use the generated AuTest wrapper from the build tree:

```bash
./build/dev-external/autest.sh
```

When a change is localized, prefer running the relevant AuTest subset with
`-f ...` instead of the full suite.

## Formatting And File Structure

- Use the repository `.clang-format`. The project style includes 2-space
  indentation, 100-column lines, preserved include blocks, and brace placement
  consistent with the existing headers and sources. At any time, you can format
  the entire codebase with `tools/format.sh`.
- Keep the existing file prologue pattern:
  Doxygen `@file` comment plus SPDX header.
- Prefer header / implementation separation for non-trivial types.
- Avoid gratuitous include churn. `SortIncludes` is disabled, so follow the
  surrounding file's include ordering unless there is a real reason to change
  it.
- Almost all new files should contain the Apache license preface with this year
  referenced as the copyright, except of course files that cannot contain such
  comments, such as `.json` files and autest `.gold` files.
- Replay YAML files, including AuTest replay files under `tests/autests`, also
  need the same commented file prologue (`# @file`, copyright, SPDX). Do not
  add new replay YAMLs without that header.

## C++ Style

- Use modern C++20 features when they improve clarity or safety.
  Good fits in this repo include `enum class`, defaulted special members,
  designated initializers in tests, chrono literals, structured bindings, and
  stronger type wrappers over raw primitives.
- Prefer `std::chrono` and chrono literals over c-time constructs for timeouts,
  delays, and time math.
- Prefer `swoc::Errata`, `swoc::Rv<T>`, `swoc::BufferWriter`, and related SWOC
  helpers where the surrounding code already uses them.
- Prefer scoped enums, `constexpr`, `inline constexpr`, and typed constants over
  macros and anonymous literals.

## Parsing And String Handling

- When parsing strings, tokenizing input, or otherwise working with
  `std::string_view`, strongly consider `swoc::TextView` first. The codebase
  already uses it heavily for HTTP parsing, replay parsing, and rule handling,
  and it often leads to shorter, clearer parsing logic.
- Accept non-owning string inputs as `swoc::TextView` or `std::string_view`
  when ownership is not required. Convert to `std::string` only when storage or
  mutation is needed.
- Preserve existing replay-file parsing behavior unless the change explicitly
  intends to extend it in a backwards-compatible way.

## Class And Struct Conventions

- In classes and structs, use two of `public:`, `protected:`, 
  `private:`, as appropriate, to separate public member functions from public
  member variables, protected member functions from protected member variables,
  etc., to provide a clean visual break between member functions and member
  variables.
- For new private member variables, use an `m_` prefix.

## Constants And Call Sites

- Prefer right side const: `auto const` instead of `const auto`.
- Avoid raw literals at call sites, especially booleans and magic numbers.
- Define named `constexpr` values near the relevant API or type so call sites
  remain self-documenting.
- For boolean flags, generally declare only the truthy form and let callers use
  negation when needed.

Example:

```c++
constexpr bool IGNORE_CASE = true;
do_something(IGNORE_CASE);
do_something(!IGNORE_CASE);
```

## Documentation

- Add Doxygen comments for public functions.
- Add Doxygen comments for public members and for public functions of classes
  and structs.
- Keep comments high-signal: explain behavior, invariants, ownership,
  compatibility constraints, and protocol subtleties rather than narrating
  obvious syntax.
- If a change affects CLI flags, replay YAML, verification semantics, or build
  workflows, update `README.md` in the same change when appropriate.

## Testing Patterns

- Unit tests live under `tests/unit_tests` and use Catch-style `TEST_CASE`
  naming with descriptive behavior-oriented titles.
- Table-driven tests and designated initializers are already used and are good
  patterns to continue when they improve clarity.
- End-to-end behavior belongs in AuTests under `tests/autests/gold_tests`.
- For parser, protocol, replay, CLI, or compatibility fixes, prefer adding a
  regression test alongside the code change.

## Compatibility Checklist

Before finishing a change, sanity-check:

- Does the change preserve existing CLI argument forms?
- Does it preserve existing YAML schema and replay semantics?
- Does it keep current diagnostics and docs accurate enough?
- Should `README.md` change?
- Should a unit test or AuTest be added?
