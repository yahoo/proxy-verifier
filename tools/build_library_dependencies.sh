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
git clone -b openssl-3.0.1+quic --depth 1 https://github.com/quictls/openssl.git openssl
cd openssl
git checkout ab8b87bdb436b11bf2a10a2a57a897722224f828
# Installing to lib instead of the default system lib64 makes linking work
# better in our setup.
./config --prefix=${install_dir}/openssl --libdir=lib
make -j4
${SUDO} make install_sw

# 2. nghttp3
cd ${repo_dir}
git clone https://github.com/ngtcp2/nghttp3
cd nghttp3/
git checkout 69e381358697a5c924860dbc256a2d0ee44448a3
autoreconf -i
./configure --prefix=${install_dir}/nghttp3 --enable-lib-only
make -j4
${SUDO} make install

# 3. ngtcp2
cd ${repo_dir}
git clone https://github.com/ngtcp2/ngtcp2
cd ngtcp2
git checkout 9b6fdfb135475e9ed480d87e98c4717683f63e33
autoreconf -i
./configure \
  PKG_CONFIG_PATH=${install_dir}/openssl/lib64/pkgconfig:${install_dir}/openssl/lib/pkgconfig:${install_dir}/nghttp3/lib/pkgconfig \
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
# commit 8a552631b4e64851018947a44b98fa022133fa81 (HEAD -> master, origin/master, origin/HEAD)
# Merge: cff81069 deb390cf
# Author: Tatsuhiro Tsujikawa <404610+tatsuhiro-t@users.noreply.github.com>
# Date:   Tue Jan 11 20:53:08 2022 +0900
#
#     Merge pull request #1667 from nghttp2/keep-hd-table-size
#
#     Fix decoder table size update
git checkout 8a552631b4e64851018947a44b98fa022133fa81

autoreconf -if
./configure \
  PKG_CONFIG_PATH=${install_dir}/openssl/lib/pkgconfig:${install_dir}/ngtcp2/lib/pkgconfig:${install_dir}/nghttp3/lib/pkgconfig \
  --prefix=${install_dir}/nghttp2 \
  --enable-lib-only
make -j $(nproc)
${SUDO} make install
