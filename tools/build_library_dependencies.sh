#!/bin/bash
#
# Build QUIC/HTTP3 library dependencies.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

fail() {
  echo "$1"
  exit 1
}

set -euo pipefail
set -x

OPENSSL_TAG=openssl-3.5.5
NGHTTP3_TAG=v1.15.0
NGTCP2_TAG=v1.21.0
NGHTTP2_TAG=v1.68.0

os=$(uname)
[ "${os}" = "Linux" ] || [ "${os}" = "Darwin" ] || fail "Unrecognized OS: ${os}"

for tool in git make pkg-config autoreconf autoconf automake
do
  command -v "${tool}" >/dev/null 2>&1 || fail "Missing required tool: ${tool}"
done

if [ "${os}" = "Linux" ]
then
  num_threads=$(nproc)
else
  num_threads=$(sysctl -n hw.logicalcpu)
  export CC="$(xcrun -find clang)"
  export CXX="$(xcrun -find clang++)"
  export SDKROOT="$(xcrun --show-sdk-path)"
fi

[ $# -eq 1 ] || fail "Please provide a directory in which to install the libraries."
install_dir=$1

echo
echo "Building with ${num_threads} threads, installing in ${install_dir}"
echo

SUDO=""
[ -d "${install_dir}" ] || mkdir -p "${install_dir}" || {
  command -v sudo >/dev/null 2>&1 || fail "Cannot create ${install_dir} without sudo"
  sudo mkdir -p "${install_dir}"
}
[ -w "${install_dir}" ] || {
  command -v sudo >/dev/null 2>&1 || fail "Cannot write to ${install_dir} without sudo"
  SUDO=sudo
}

chmod_with_permissions() {
  local target_dir=$1

  if [ -n "${SUDO}" ]
  then
    sudo chmod -R ugo+rX "${target_dir}"
  else
    chmod -R ugo+rX "${target_dir}"
  fi
}

chmod_with_permissions "${install_dir}"

mkdir -p "${install_dir}"
repo_dir=$(mktemp -d /var/tmp/http3_dependency_repos_XXXXXX)
cleanup() {
  rm -rf "${repo_dir}"
}
trap cleanup EXIT

autoreconf --version >/dev/null 2>&1 || fail \
  "autoreconf is not runnable; please fix your autotools install"
autoconf --version >/dev/null 2>&1 || fail \
  "autoconf is not runnable; please fix your autotools install"
automake --version >/dev/null 2>&1 || fail \
  "automake is not runnable; please fix your autotools install"

clone_tagged_repo() {
  local repo_url=$1
  local repo_name=$2
  local repo_tag=$3

  git clone --branch "${repo_tag}" --depth 1 "${repo_url}" "${repo_name}"
}

install_with_permissions() {
  local target_dir=$1

  ${SUDO} make install
  chmod_with_permissions "${target_dir}"
}

cd "${repo_dir}"

# 1. OpenSSL with built-in QUIC support.
clone_tagged_repo https://github.com/openssl/openssl.git openssl "${OPENSSL_TAG}"
cd openssl
./config enable-tls1_3 --prefix="${install_dir}/openssl" --libdir=lib
make -j "${num_threads}"
${SUDO} make install_sw
chmod_with_permissions "${install_dir}/openssl"

# 2. nghttp3
cd "${repo_dir}"
clone_tagged_repo https://github.com/ngtcp2/nghttp3.git nghttp3 "${NGHTTP3_TAG}"
cd nghttp3
git submodule update --init
autoreconf -if
./configure --prefix="${install_dir}/nghttp3" --enable-lib-only
make -j "${num_threads}"
install_with_permissions "${install_dir}/nghttp3"

# 3. ngtcp2
cd "${repo_dir}"
clone_tagged_repo https://github.com/ngtcp2/ngtcp2.git ngtcp2 "${NGTCP2_TAG}"
cd ngtcp2
git submodule update --init
autoreconf -if
PKG_CONFIG_PATH="${install_dir}/openssl/lib/pkgconfig:${install_dir}/nghttp3/lib/pkgconfig" \
LDFLAGS="-Wl,-rpath,${install_dir}/openssl/lib" \
./configure \
  --prefix="${install_dir}/ngtcp2" \
  --enable-lib-only
make -j "${num_threads}"
install_with_permissions "${install_dir}/ngtcp2"

# 4. nghttp2
cd "${repo_dir}"
clone_tagged_repo https://github.com/nghttp2/nghttp2.git nghttp2 "${NGHTTP2_TAG}"
cd nghttp2
git submodule update --init
autoreconf -if
PKG_CONFIG_PATH="${install_dir}/openssl/lib/pkgconfig:${install_dir}/ngtcp2/lib/pkgconfig:${install_dir}/nghttp3/lib/pkgconfig" \
./configure \
  --prefix="${install_dir}/nghttp2" \
  --enable-lib-only
make -j "${num_threads}"
install_with_permissions "${install_dir}/nghttp2"
