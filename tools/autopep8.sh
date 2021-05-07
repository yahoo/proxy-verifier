#! /usr/bin/env bash
#
# Run autopep8 on our Python source files.
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

# Update the PKGVERSION with the new desired autopep8 tag when a new autopep8
# version is desired.
# See:
# https://github.com/hhatto/autopep8/tags
AUTOPEP8_VERSION="1.5.3"

VERSION="autopep8 1.5.3 (pycodestyle: 2.6.0)"

# Tie this to exactly the pycodestyle version that shows up in the setup.py of
# autopep8 so we know we run with the same version each time.
# See:
# https://github.com/hhatto/autopep8/blob/master/setup.py
PYCODESTYLE_TAG="2.6.0"

fail()
{
  echo $1
  exit 1
}

function main() {
  set -e # exit on error

  if ! type pipenv >/dev/null 2>/dev/null
  then
    fail "Please install pipenv."
  fi

  if ! type virtualenv >/dev/null 2>/dev/null
  then
    pip install -q virtualenv
  fi

  AUTOPEP8_VENV=${AUTOPEP8_VENV:-$(cd $(dirname $0) && git rev-parse --show-toplevel)/.git/fmt/autopep8_${AUTOPEP8_VERSION}_venv}
  if [ ! -e ${AUTOPEP8_VENV} ]
  then
    virtualenv ${AUTOPEP8_VENV}
  fi
  source ${AUTOPEP8_VENV}/bin/activate

  pip install -q "pycodestyle==${PYCODESTYLE_TAG}"
  pip install -q "autopep8==${AUTOPEP8_VERSION}"

  ver=$(autopep8 --version 2>&1)
  if [ "$ver" != "$VERSION" ]
  then
      echo "Wrong version of autopep8!"
      echo "Expected: \"${VERSION}\", got: \"${ver}\""
      exit 1
  fi

  DIR=${@:-.}

  # Only run autopep8 on tracked files. This saves time and possibly avoids
  # formatting files the user doesn't want formatted.
  tmp_dir=$(mktemp -d -t tracked-git-files.XXXXXXXXXX)
  files=${tmp_dir}/git_files.txt
  files_filtered=${tmp_dir}/git_files_filtered.txt
  git ls-tree -r HEAD --name-only ${DIR} | grep -vE "lib/yamlcpp" > ${files}
  # Add to the above any newly added staged files.
  git diff --cached --name-only --diff-filter=A >> ${files}
  # Keep this list of Python extensions the same with the list of
  # extensions searched for in the tools/git/pre-commit hook.
  grep -E '\.part$|\.py$|\.cli.ext$|\.test.ext$' ${files} > ${files_filtered}

  echo "Running autopep8. This may take a minute."
  autopep8 \
      --ignore-local-config \
      -i \
      -j 0 \
      --max-line-length 100 \
      --aggressive \
      --aggressive \
      $(cat ${files_filtered})
  echo "autopep8 completed."
  rm -rf ${tmp_dir}
  deactivate
}

if [[ "$(basename -- "$0")" == 'autopep8.sh' ]]; then
  main "$@"
else
  AUTOPEP8_VENV=${AUTOPEP8_VENV:-$(git rev-parse --show-toplevel)/.git/fmt/autopep8_${AUTOPEP8_VERSION}_venv}
fi
