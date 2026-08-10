#! /usr/bin/env bash
#
# Update Copyrights to the year of each file's most recent commit.
# If a commit is provided, limit the update to files changed by that commit.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

usage="$(basename "$0") [git_commit]"

fail()
{
  printf '%b\n' "$1" >&2
  exit 1
}
[ $# -le 1 ] || fail "Provide at most one git commit.\n\n${usage}"
commit=${1:-}
copyright_owners='(Verizon Media|Yahoo)'
copyright_range='(Copyright [[:digit:]]{4}-)[[:digit:]]{4}'
copyright_single='(Copyright [[:digit:]]{4})'
copyright_pattern="Copyright ([[:digit:]]{4})(-([[:digit:]]{4}))?, ${copyright_owners}"
tools_dir=$(dirname "$0")
git_root=$(dirname "${tools_dir}")
cd "${git_root}" || fail "Could not enter the git worktree: ${git_root}"

if [ -n "${commit}" ]; then
  git rev-parse --verify "${commit}^{commit}" >/dev/null 2>&1 || \
    fail "Could not resolve git commit: ${commit}\n\n${usage}"
fi
[ "$(git rev-parse --is-shallow-repository)" = "false" ] || \
  fail "A complete git history is required to determine copyright years."

selected_files=$(mktemp "${TMPDIR:-/tmp}/copyright-update.XXXXXX") || \
  fail "Could not create a temporary file."
cleanup()
{
  rm -f -- "${selected_files}"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ -n "${commit}" ]; then
  git diff-tree --no-commit-id --name-only --diff-filter=ACMRTUXB -r \
    "${commit}" > "${selected_files}"
else
  git ls-files > "${selected_files}"
fi

# A single history traversal avoids invoking git once for every tracked file.
git log --format='CopyrightYear:%cd' --date=format:%Y --name-only \
  --diff-filter=ACMRTUXB HEAD -- |
  awk '
    NR == FNR {
      selected[$0] = 1
      next
    }
    /^CopyrightYear:[[:digit:]]{4}$/ {
      year = substr($0, 15)
      next
    }
    year != "" && $0 in selected && !seen[$0]++ {
      print year "\t" $0
    }
  ' "${selected_files}" - |
  while IFS="$(printf '\t')" read -r last_commit_year tracked_file; do
    [ -f "${tracked_file}" ] || continue
    # Do not alter copyrights embedded in vendored sources.
    copyright=$(grep -Em1 "${copyright_pattern}" "${tracked_file}") || continue
    [[ "${copyright}" =~ ${copyright_pattern} ]] || continue
    first_year=${BASH_REMATCH[1]}
    last_header_year=${BASH_REMATCH[3]}

    backup_suffix=".copyright-update.$$"
    if [ -n "${last_header_year}" ]; then
      [ "${last_header_year}" != "${last_commit_year}" ] || continue
      # A range retains its starting year; only its ending year changes.
      sed -E -i"${backup_suffix}" \
        -e "s/${copyright_range}(, ${copyright_owners})/\\1${last_commit_year}\\2/g" \
        "${tracked_file}"
    else
      [ "${first_year}" != "${last_commit_year}" ] || continue
      # Preserve the first year by extending a single year into a range.
      sed -E -i"${backup_suffix}" \
        -e "s/${copyright_single}(, ${copyright_owners})/\\1-${last_commit_year}\\2/g" \
        "${tracked_file}"
    fi
    rm -f -- "${tracked_file}${backup_suffix}"
  done
