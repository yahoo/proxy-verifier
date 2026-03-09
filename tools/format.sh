#! /usr/bin/env bash
#
# Run our various code formatting tools.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

fail()
{
  echo $1
  exit 1
}

parent_dir="$(dirname -- "$0")"
clang_format_sh="${parent_dir}/clang-format.sh"
[ -r "${clang_format_sh}" ] || fail "Could not find clang-format.sh"
cmake_format_sh="${parent_dir}/cmake-format.sh"
[ -r "${cmake_format_sh}" ] || fail "Could not find cmake-format.sh"
yapf_sh="${parent_dir}/yapf.sh"
[ -r "${yapf_sh}" ] || fail "Could not find yapf.sh"

bash ${clang_format_sh}
bash ${cmake_format_sh}
bash ${yapf_sh}
