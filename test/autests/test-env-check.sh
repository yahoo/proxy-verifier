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
    exit 1
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
    exit 1
fi

# check for pipenv
pipenv --version &> /dev/null
if [ $? -eq 0 ]; then
    echo "pipenv detected!"
    pipenv --venv &> /dev/null
    if [ $? -ne 0 ]; then
        echo "Installing a new virtual environment via pipenv"
        pipenv install
    else
        echo "Using the pre-existing virtual environment."
    fi
else
    echo "pipenv is not installed/enabled. "
fi
