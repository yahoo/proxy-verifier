#!/bin/bash
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


# check for python3
python3 - << _END_
import sys

if sys.version_info.major < 3 or sys.version_info.minor < 10:
    exit(1)
_END_

if [ $? = 1 ]
then
    echo "Python 3.10 or newer is not installed/enabled."
    exit 1
else
    echo "Python 3.10 or newer detected!"
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

# check for uv
uv --version &> /dev/null
if [ $? -eq 0 ]; then
    echo "uv detected!"

    recreate_venv=false
    if [ ! -d .venv ]; then
        recreate_venv=true
    elif ! .venv/bin/python3 --version &> /dev/null; then
        echo "The existing virtual environment is stale. Recreating it."
        recreate_venv=true
    elif ! .venv/bin/autest --help &> /dev/null; then
        echo "The existing AuTest entry point is stale. Recreating the virtual environment."
        recreate_venv=true
    fi

    if [ "${recreate_venv}" = true ]; then
        rm -rf .venv
        echo "Installing a new virtual environment via uv"

        os_name=$(uname)
        if [ "${os_name}" == "Darwin" ]
        then
          # MacOS has its own SSL version. The PyOpenSSL Python package
          # installed via the following uv command will build the
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

        uv sync
    else
        echo "Using the pre-existing virtual environment."
    fi
else
    echo "uv is not installed/enabled. "
    exit 1
fi
