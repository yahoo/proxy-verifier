#! /usr/bin/env bash
#
# Run cmake-format on tracked CMake files.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

set -euo pipefail

CMAKE_FORMAT_VERSION="0.6.13"

fail() {
  echo "$1"
  exit 1
}

main() {
  if ! command -v uv >/dev/null 2>&1; then
    fail "uv is not installed. Please install it before running cmake-format."
  fi

  local version
  version="$(uv tool run --quiet --from "cmakelang@${CMAKE_FORMAT_VERSION}" --with pyaml cmake-format --version 2>&1)"
  if [[ "${version}" != "${CMAKE_FORMAT_VERSION}" ]]; then
    fail "Wrong version of cmake-format: expected ${CMAKE_FORMAT_VERSION}, got ${version}"
  fi

  local target_dir="${1:-.}"
  local tmp_dir
  tmp_dir="$(mktemp -d -t tracked-git-files.XXXXXXXXXX)"
  local files="${tmp_dir}/git_files.txt"
  local files_filtered="${tmp_dir}/git_files_filtered.txt"

  git ls-tree -r HEAD --name-only "${target_dir}" > "${files}"
  git diff --cached --name-only --diff-filter=A >> "${files}"
  grep -E '(^|/)CMakeLists.txt$|\.cmake$' "${files}" > "${files_filtered}" || true

  if [[ ! -s "${files_filtered}" ]]; then
    rm -rf "${tmp_dir}"
    return 0
  fi

  sed -i'.bak' 's:^:\./:' "${files_filtered}"
  rm -f "${files_filtered}.bak"

  local start_time_file="${tmp_dir}/format_start.$$"
  touch "${start_time_file}"
  uv tool run --quiet --from "cmakelang@${CMAKE_FORMAT_VERSION}" --with pyaml \
    cmake-format -i $(cat "${files_filtered}")
  find $(cat "${files_filtered}") -newer "${start_time_file}"

  rm -rf "${tmp_dir}"
}

if [[ "$(basename -- "$0")" == 'cmake-format.sh' ]]; then
  main "$@"
fi
