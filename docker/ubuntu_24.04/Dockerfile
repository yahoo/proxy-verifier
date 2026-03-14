#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM ubuntu:24.04 AS pv-libs-builder-base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG DEBIAN_FRONTEND=noninteractive

ENV PATH="/opt/pv-venv/bin:${PATH}" \
    PV_DEPS_ROOT="/opt/pv_libs"

RUN <<'EOF'
set -eux

apt-get update
apt-get install -y --no-install-recommends \
  autoconf \
  automake \
  ca-certificates \
  curl \
  diffutils \
  g++ \
  gcc \
  git \
  libc6-dev \
  libffi-dev \
  libssl-dev \
  libtool \
  make \
  perl \
  pkg-config \
  sudo \
  python3-dev \
  python3-pip \
  python3-venv

python3 -m venv /opt/pv-venv
/opt/pv-venv/bin/pip install --upgrade pip
/opt/pv-venv/bin/pip install --no-cache-dir "cmake==4.2.3" ninja uv

rm -rf /var/lib/apt/lists/*
EOF

# Build the HTTP dependency stack once during image creation.
FROM pv-libs-builder-base AS pv-libs-builder

ARG PV_REPO_URL="https://github.com/yahoo/proxy-verifier.git"
ARG PV_REPO_REF="master"

RUN <<'EOF'
set -eux

git clone --depth 1 --branch "${PV_REPO_REF}" "${PV_REPO_URL}" /tmp/proxy-verifier
chmod +x /tmp/proxy-verifier/tools/build_library_dependencies.sh
/tmp/proxy-verifier/tools/build_library_dependencies.sh /opt/pv_libs
rm -rf /tmp/proxy-verifier
EOF

# The final image is the development environment used to build, test,
# and produce release binaries with the prebuilt /opt/pv_libs tree.
FROM ubuntu:24.04 AS dev

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG DEBIAN_FRONTEND=noninteractive

ENV PATH="/opt/pv-venv/bin:${PATH}" \
    PV_DEPS_ROOT="/opt/pv_libs"

RUN <<'EOF'
set -eux

apt-get update
apt-get install -y --no-install-recommends \
  autoconf \
  automake \
  ca-certificates \
  curl \
  diffutils \
  g++ \
  gcc \
  git \
  libc6-dev \
  libffi-dev \
  libssl-dev \
  libtool \
  make \
  perl \
  pkg-config \
  sudo \
  python3-dev \
  python3-pip \
  python3-venv

python3 -m venv /opt/pv-venv
/opt/pv-venv/bin/pip install --upgrade pip
/opt/pv-venv/bin/pip install --no-cache-dir "cmake==4.2.3" ninja uv

rm -rf /var/lib/apt/lists/*
EOF

COPY --from=pv-libs-builder /opt/pv_libs /opt/pv_libs

WORKDIR /workspace
