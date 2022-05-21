#!/bin/bash
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

fail()
{
  echo $1
  exit 1
}

pushd $(dirname $0) > /dev/null
export PYTHONPATH=$(pwd):$PYTHONPATH
./test-env-check.sh || fail "Setting up the test environment failed."
# this is for rhel or centos systems
echo "Environment config finished. Running AuTest..."
pipenv run autest -D gold_tests "$@"
ret=$?
popd > /dev/null
exit $ret
