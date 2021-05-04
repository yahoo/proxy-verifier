#!/bin/bash
#
# Build QUIC/HTTP3 library dependencies.
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

# Inspired by:
# https://github.com/curl/curl/blob/master/docs/HTTP3.md

fail()
{
  echo $1
  exit 1
}

[ $# -eq 1 ] || fail "Please provide a directory in which to install the libraries."
install_dir=$1

# Only try using sudo if the install directory is not writable by the current
# user.
SUDO=""
[ -w "${install_dir}" ] || SUDO=sudo

mkdir -p ${install_dir}
repo_dir=/var/tmp/http3_dependency_repos_$$
mkdir -p ${repo_dir}

# 1. OpenSSL version that supports quic.
cd ${repo_dir}
git clone --depth 1 -b OpenSSL_1_1_1g-quic-draft-33 https://github.com/tatsuhiro-t/openssl
cd openssl
git checkout afdc16c82f724e8c0b8384224180b140fe8566fe
./config enable-tls1_3 --prefix=${install_dir}/openssl
make -j4
${SUDO} make install_sw

# 2. nghttp3
cd ${repo_dir}
git clone https://github.com/ngtcp2/nghttp3
cd nghttp3/
git checkout aed3107f9104eae77d97ed8093caa8f3b7ef64d4
autoreconf -i
./configure --prefix=${install_dir}/nghttp3 --enable-lib-only
make -j4
${SUDO} make install

# 3. ngtcp2
cd ${repo_dir}
git clone https://github.com/ngtcp2/ngtcp2
cd ngtcp2
git checkout 169c68127b78ea906c96b49b9e18d4f805ab8eda
autoreconf -i
./configure \
  PKG_CONFIG_PATH=${install_dir}/openssl/lib/pkgconfig:${install_dir}/nghttp3/lib/pkgconfig \
  LDFLAGS="-Wl,-rpath,${install_dir}/openssl/lib" \
  --prefix=${install_dir}/ngtcp2 \
  --enable-lib-only
make -j4
${SUDO} make install

#4. nghttp2
cd ${repo_dir}
git clone https://github.com/tatsuhiro-t/nghttp2.git
cd nghttp2
git checkout d2e570c72e169ed88557ce5108df34d34d4f7f08
autoreconf -if
./configure \
  --prefix=${install_dir}/nghttp2 \
  PKG_CONFIG_PATH=${install_dir}/openssl/lib/pkgconfig
make -j $(nproc)
${SUDO} make install
