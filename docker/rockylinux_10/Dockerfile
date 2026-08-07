#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM docker.io/rockylinux/rockylinux:10 AS dev-base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV PATH="/opt/pv-venv/bin:${PATH}" \
    PV_DEPS_ROOT="/opt/pv_libs"

RUN <<'EOF'
set -eux

dnf install -y dnf-plugins-core
dnf config-manager --set-enabled crb
dnf install -y \
  ca-certificates \
  curl \
  diffutils \
  gcc \
  gcc-c++ \
  git \
  glibc-static \
  libffi-devel \
  libstdc++-static \
  openssl-devel \
  procps-ng \
  pkgconf-pkg-config \
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

FROM dev-base AS deps-builder

RUN <<'EOF'
set -eux

dnf install -y \
  autoconf \
  automake \
  libtool \
  make \
  perl

dnf clean all
rm -rf /var/cache/dnf
EOF

COPY tools/build-library-dependencies.sh /tmp/build-library-dependencies.sh

RUN <<'EOF'
set -eux

chmod +x /tmp/build-library-dependencies.sh
/tmp/build-library-dependencies.sh /opt/pv_libs
rm -f /tmp/build-library-dependencies.sh
EOF

FROM dev-base AS dev-external

COPY --from=deps-builder /opt/pv_libs /opt/pv_libs

WORKDIR /workspace

FROM deps-builder AS dev

WORKDIR /workspace
