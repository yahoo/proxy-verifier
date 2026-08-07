#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM docker.io/library/alpine:3.20 AS dev-base

ENV PATH="/opt/pv-venv/bin:${PATH}" \
    PV_DEPS_ROOT="/opt/pv_libs"

RUN apk add --no-cache \
  bash \
  build-base \
  ca-certificates \
  coreutils \
  curl \
  diffutils \
  git \
  libffi-dev \
  linux-headers \
  openssl-dev \
  pkgconf \
  python3 \
  python3-dev \
  py3-pip

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN <<'EOF'
set -eux

python3 -m venv /opt/pv-venv
/opt/pv-venv/bin/pip install --upgrade pip
/opt/pv-venv/bin/pip install --no-cache-dir "cmake==4.2.3" ninja uv
cat >/etc/profile.d/pv-venv.sh <<'PROFILE'
export PATH="/opt/pv-venv/bin:${PATH}"
PROFILE
EOF

FROM dev-base AS deps-builder

RUN apk add --no-cache \
  autoconf \
  automake \
  libtool \
  perl

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
