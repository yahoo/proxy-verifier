#!/bin/bash
#
# Build HTTP and QUIC library dependencies.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

fail() {
  echo "$1"
  exit 1
}

usage() {
  cat <<'EOF'
Usage: tools/build-library-dependencies.sh [--portable] <install-dir>

Build OpenSSL 3.5, nghttp2, and nghttp3 into <install-dir>.

Use --portable to add conservative Linux amd64 baseline flags suitable for
portable release builds.
EOF
}

set -euo pipefail

OPENSSL_TAG=openssl-3.5.7
NGHTTP3_TAG=v1.15.0
NGHTTP2_TAG=v1.68.0

os=$(uname)
[ "${os}" = "Linux" ] || [ "${os}" = "Darwin" ] || fail "Unrecognized OS: ${os}"
arch=$(uname -m)

portable_build=false
args=()
while [ $# -gt 0 ]
do
  case "$1" in
    --portable)
      portable_build=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      usage
      fail "Unrecognized option: $1"
      ;;
    *)
      args+=("$1")
      ;;
  esac
  shift
done

if [ $# -gt 0 ]
then
  args+=("$@")
fi

[ "${#args[@]}" -eq 1 ] || {
  usage
  fail "Please provide a directory in which to install the libraries."
}
install_dir=${args[0]}

set -x

portable_cpu_flags=""
if [ "${portable_build}" = true ] &&
   [ "${os}" = "Linux" ] &&
   { [ "${arch}" = "x86_64" ] || [ "${arch}" = "amd64" ]; }
then
  portable_cpu_flags="-march=x86-64 -mtune=generic"
fi

for tool in git make perl pkg-config autoreconf autoconf automake
do
  command -v "${tool}" >/dev/null 2>&1 || fail "Missing required tool: ${tool}"
done
perl -MTime::Piece -e 1 >/dev/null 2>&1 || fail \
  "Missing required Perl module: Time::Piece"

if [ "${os}" = "Linux" ]
then
  num_threads=$(nproc)
else
  num_threads=$(sysctl -n hw.logicalcpu)
fi

echo
echo "Building with ${num_threads} threads, installing in ${install_dir}"
if [ -n "${portable_cpu_flags}" ]
then
  echo "Using conservative amd64 baseline flags: ${portable_cpu_flags}"
elif [ "${portable_build}" = true ]
then
  echo "Portable mode requested; no additional CPU baseline flags are needed for ${os}/${arch}."
fi
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

append_env_flags() {
  local var_name=$1
  local extra_flags=$2
  local current_value=${!var_name-}

  if [ -z "${extra_flags}" ]
  then
    return
  fi

  if [ -n "${current_value}" ]
  then
    printf -v "${var_name}" '%s %s' "${current_value}" "${extra_flags}"
  else
    printf -v "${var_name}" '%s' "${extra_flags}"
  fi
  export "${var_name}"
}

append_env_flags CFLAGS "${portable_cpu_flags}"
append_env_flags CXXFLAGS "${portable_cpu_flags}"

mkdir -p "${install_dir}"
repo_dir=$(mktemp -d /var/tmp/http_dependency_repos_XXXXXX)
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

# OpenSSL with built-in QUIC support.
clone_tagged_repo https://github.com/openssl/openssl.git openssl "${OPENSSL_TAG}"
cd openssl
./config enable-tls1_3 --prefix="${install_dir}/openssl" --libdir=lib
make -j "${num_threads}"
${SUDO} make install_sw
chmod_with_permissions "${install_dir}/openssl"

# nghttp3 provides HTTP/3 framing and QPACK.
cd "${repo_dir}"
clone_tagged_repo https://github.com/ngtcp2/nghttp3.git nghttp3 "${NGHTTP3_TAG}"
cd nghttp3
git submodule update --init
autoreconf -if
./configure --prefix="${install_dir}/nghttp3" --enable-lib-only
make -j "${num_threads}"
install_with_permissions "${install_dir}/nghttp3"

# nghttp2 provides HTTP/2 framing and HPACK.
cd "${repo_dir}"
clone_tagged_repo https://github.com/nghttp2/nghttp2.git nghttp2 "${NGHTTP2_TAG}"
cd nghttp2
git submodule update --init
autoreconf -if
./configure --prefix="${install_dir}/nghttp2" --enable-lib-only
make -j "${num_threads}"
install_with_permissions "${install_dir}/nghttp2"
