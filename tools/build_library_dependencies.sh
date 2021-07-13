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
[ -d "${install_dir}" ] || \
    mkdir -p ${install_dir} || \
    sudo mkdir -p ${install_dir}
[ -w "${install_dir}" ] || SUDO=sudo

mkdir -p ${install_dir}
repo_dir=/var/tmp/http3_dependency_repos_$$
mkdir -p ${repo_dir}

# 1. OpenSSL version that supports quic.
cd ${repo_dir}
git clone -b OpenSSL_1_1_1k+quic --depth 1 https://github.com/quictls/openssl.git openssl
cd openssl
git checkout a6e9d76db343605dae9b59d71d2811b195ae7434
./config --prefix=${install_dir}/openssl
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

# This commit will be removed whenever the nghttp2 author rebases origin/quic.
# For reference, this commit is currently described as:
#
# commit cdf58e370e6a843b0965aabcd75908ca52633b60
# Author: Tatsuhiro Tsujikawa <tatsuhiro.t@gmail.com>
# Date:   Sat Mar 27 23:37:37 2021 +0900
#
#     Compile with the latest ngtcp2

git checkout cdf58e370e6a843b0965aabcd75908ca52633b60

autoreconf -if
./configure \
  PKG_CONFIG_PATH=${install_dir}/openssl/lib/pkgconfig:${install_dir}/ngtcp2/lib/pkgconfig:${install_dir}/nghttp3/lib/pkgconfig \
  --prefix=${install_dir}/nghttp2 \
  --enable-lib-only
make -j $(nproc)
${SUDO} make install
