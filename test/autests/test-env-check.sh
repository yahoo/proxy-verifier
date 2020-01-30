#!/bin/bash
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


# check for python3
python3 - << _END_
import sys

if sys.version_info.major < 3 or sys.version_info.minor < 5:
    exit(1)
_END_

if [ $? = 1 ]
then
    echo "Python 3.5 or newer is not installed/enabled."
    return
else
    echo "Python 3.5 or newer detected!"
fi

# check for python development header -- for autest
python3-config &> /dev/null
if [ $? = 1 ]
then
    echo "python3-dev/devel detected!"
else
    echo "python3-dev/devel is not installed. "
    return
fi

# check for pipenv
pipenv --version &> /dev/null
if [ $? = 0 ]
then
    echo "pipenv detected!"
    pipenv install
    # pipenv shell
else
    echo "pipenv is not installed/enabled. "
fi
