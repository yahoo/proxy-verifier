#! /usr/bin/env bash
#
# Run yapf on our Python source files.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

YAPF_VERSION="0.43.0"
VERSION="yapf 0.43.0"

fail()
{
  echo "$1"
  exit 1
}

function main() {
  set -e

  if ! command -v uv >/dev/null 2>/dev/null
  then
    fail "Please install uv."
  fi

  ver=$(uv tool run --quiet "yapf@${YAPF_VERSION}" --version 2>&1)
  if [ "$ver" != "$VERSION" ]
  then
    echo "Wrong version of yapf!"
    echo "Expected: \"${VERSION}\", got: \"${ver}\""
    exit 1
  fi

  REPO_ROOT=$(cd "$(dirname "$0")" && git rev-parse --show-toplevel)
  DIR=${@:-.}

  tmp_dir=$(mktemp -d -t tracked-git-files.XXXXXXXXXX)
  files=${tmp_dir}/git_files.txt
  files_filtered=${tmp_dir}/git_files_filtered.txt
  git ls-tree -r HEAD --name-only ${DIR} | grep -vE "lib/yamlcpp" > ${files}
  git diff --cached --name-only --diff-filter=A >> ${files}
  grep -E '\.part$|\.py$|\.cli.ext$|\.test.ext$' ${files} > ${files_filtered}
  grep -rl '#!.*python' "${REPO_ROOT}/tools" | grep -vE '(yapf.sh|.py)' | sed "s:${REPO_ROOT}/::g" >> ${files_filtered}

  if [ ! -s "${files_filtered}" ]
  then
    rm -rf "${tmp_dir}"
    exit 0
  fi

  echo "Running yapf. This may take a minute."
  YAPF_CONFIG=${REPO_ROOT}/.style.yapf
  start_time_file=${tmp_dir}/format_start.$$
  touch ${start_time_file}
  uv tool run --quiet "yapf@${YAPF_VERSION}" \
      --style "${YAPF_CONFIG}" \
      --parallel \
      --in-place \
      $(cat ${files_filtered})
  find $(cat ${files_filtered}) -newer ${start_time_file}
  echo "yapf completed."
  rm -rf "${tmp_dir}"
}

if [[ "$(basename -- "$0")" == 'yapf.sh' ]]; then
  main "$@"
fi
