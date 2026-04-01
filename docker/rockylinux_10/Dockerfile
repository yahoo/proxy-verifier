#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM docker.io/rockylinux/rockylinux:10 AS pv-libs-builder-base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV PATH="/opt/pv-venv/bin:${PATH}" \
    PV_DEPS_ROOT="/opt/pv_libs"

RUN <<'EOF'
set -eux

dnf install -y dnf-plugins-core
dnf config-manager --set-enabled crb
dnf install -y \
  autoconf \
  automake \
  ca-certificates \
  curl \
  diffutils \
  gcc \
  gcc-c++ \
  git \
  glibc-static \
  libffi-devel \
  libstdc++-static \
  libtool \
  make \
  openssl-devel \
  perl \
  procps-ng \
  pkgconf-pkg-config \
  sudo \
  python3 \
  python3-devel \
  python3-pip

python3 -m venv /opt/pv-venv
/opt/pv-venv/bin/pip install --upgrade pip
/opt/pv-venv/bin/pip install --no-cache-dir "cmake==4.2.3" ninja uv
cat >/etc/profile.d/pv-venv.sh <<'PROFILE'
export PATH="/opt/pv-venv/bin:${PATH}"
PROFILE

dnf clean all
rm -rf /var/cache/dnf
EOF

# Build the HTTP dependency stack once during image creation.
FROM pv-libs-builder-base AS dev

ARG PV_REPO_URL="https://github.com/yahoo/proxy-verifier.git"
ARG PV_REPO_REF="master"

RUN <<'EOF'
set -eux

git clone --depth 1 --branch "${PV_REPO_REF}" "${PV_REPO_URL}" /tmp/proxy-verifier
chmod +x /tmp/proxy-verifier/tools/build-library-dependencies.sh
/tmp/proxy-verifier/tools/build-library-dependencies.sh /opt/pv_libs
rm -rf /tmp/proxy-verifier
EOF

WORKDIR /workspace
