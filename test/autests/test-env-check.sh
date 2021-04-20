#!/bin/bash
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


# check for python3
python3 - << _END_
import sys

if sys.version_info.major < 3 or sys.version_info.minor < 6:
    exit(1)
_END_

if [ $? = 1 ]
then
    echo "Python 3.6 or newer is not installed/enabled."
    exit 1
else
    echo "Python 3.6 or newer detected!"
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

        os_name=$(uname)
        if [ "${os_name}" == "Darwin" ]
        then
          # MacOS has its own SSL version. The PyOpenSSL Python package
          # installed via the following pipenv command will build the
          # crytpography package which will require the brew-installed openssl
          # version. We set the following variables to point the cryptography
          # build to the brew openssl.
          brew_openssl_lib="/usr/local/opt/openssl/lib"
          if [ ! -d "${brew_openssl_lib}" ]
          then
            echo "WARNING:"
            echo "Could not find ${brew_openssl_lib}. Have you run \"brew install openssl\"?"
            echo "If the cryptography package fails to install, the lack of brew's openssl may be why."
          else
            export LDFLAGS="-L/usr/local/opt/openssl/lib"
            export CPPFLAGS="-I/usr/local/opt/openssl/include"
            export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
          fi
        fi

        pipenv install
    else
        echo "Using the pre-existing virtual environment."
    fi
else
    echo "pipenv is not installed/enabled. "
fi
