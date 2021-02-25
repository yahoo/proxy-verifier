#! /usr/bin/env bash
#
# Given a commit, update all the Copyrights of the changed files.
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

usage="$(basename $0) <git_commit>"

fail()
{
  echo -e $1
  exit 1
}
[ $# -eq 1 ] || fail "Provide a git commit to check changed files for.\n\n${usage}"
commit=${1}
tools_dir=$(dirname $0)
git_root=$(dirname ${tools_dir})
cd ${git_root}
current_year=$(date +%Y)
sed -i'.sedbak' "s/Copyright 20[[:digit:]][[:digit:]]/Copyright ${current_year}/g" \
  `git diff-tree --no-commit-id --name-only -r ${commit}`
find . -name '*.sedbak' -delete
