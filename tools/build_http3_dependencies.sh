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

[ $# -eq 1 ] || fail "Please provide a directory in which to build the custom curl."
topdir=$1
mkdir -p ${topdir}
ls -1qA ${topdir} | grep -q . && fail "${topdir} is not empty."

# 1. OpenSSL version that supports quic.
cd ${topdir}
git clone --depth 1 -b OpenSSL_1_1_1g-quic-draft-33 https://github.com/tatsuhiro-t/openssl
cd openssl
git afdc16c82f724e8c0b8384224180b140fe8566fe
./config enable-tls1_3 --prefix=${topdir}/openssl_build
make -j4
make install_sw

# 2. nghttp3
cd ${topdir}
git clone https://github.com/ngtcp2/nghttp3
cd nghttp3/
git checkout aed3107f9104eae77d97ed8093caa8f3b7ef64d4
autoreconf -i
./configure --prefix=${topdir}/nghttp3_build --enable-lib-only
make -j4
make install

# 3. ngtcp2
cd ${topdir}
git clone https://github.com/ngtcp2/ngtcp2
cd ngtcp2
git checkout 169c68127b78ea906c96b49b9e18d4f805ab8eda
autoreconf -i
./configure \
  PKG_CONFIG_PATH=${topdir}/openssl_build/lib/pkgconfig:${topdir}/nghttp3_build/lib/pkgconfig \
  LDFLAGS="-Wl,-rpath,${topdir}/openssl_build/lib" \
  --prefix=${topdir}/ngtcp2_build \
  --enable-lib-only
make -j4
make install
