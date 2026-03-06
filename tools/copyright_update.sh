#! /usr/bin/env bash
#
# Given a commit, update all the Copyrights of the changed files.
# If no commit is provided, update the currently changed files in the worktree.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

usage="$(basename "$0") [git_commit]"

fail()
{
  echo -e $1
  exit 1
}
[ $# -le 1 ] || fail "Provide at most one git commit.\n\n${usage}"
commit=${1:-}
tools_dir=$(dirname "$0")
git_root=$(dirname "${tools_dir}")
cd "${git_root}"
current_year=$(date +%Y)

while IFS= read -r -d '' changed_file; do
  [ -f "${changed_file}" ] || continue
  grep -q "Copyright " "${changed_file}" || continue
  sed -i'.sedbak' \
    "s/Copyright 20[[:digit:]][[:digit:]]/Copyright ${current_year}/g" \
    "${changed_file}"
done < <(
  if [ -n "${commit}" ]; then
    git diff-tree --no-commit-id --name-only --diff-filter=ACMRTUXB -r -z "${commit}"
  else
    {
      git diff --name-only --diff-filter=ACMRTUXB -z HEAD --
      git ls-files --others --exclude-standard -z
    } | awk 'BEGIN { RS = "\0"; ORS = "\0" } !seen[$0]++'
  fi
)

find . -name '*.sedbak' -delete
