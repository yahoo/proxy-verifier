#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM docker.io/library/ubuntu:24.04 AS dev-base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG DEBIAN_FRONTEND=noninteractive
ARG RAT_VERSION=0.17
ARG RAT_SHA256=401939ebe5a52c6ed524029897bf914eaaba503d36c069ebcdbd8847a9e7cf93

ENV CC="gcc-14" \
    CXX="g++-14" \
    PATH="/opt/pv-venv/bin:${PATH}" \
    PV_DEPS_ROOT="/opt/pv_libs" \
    RAT_JAR="/opt/apache-rat/apache-rat-${RAT_VERSION}.jar"

RUN <<'EOF'
set -eux

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  clang-20 \
  curl \
  default-jre-headless \
  diffutils \
  g++-14 \
  gcc-14 \
  git \
  lbzip2 \
  libc6-dev \
  libffi-dev \
  libssl-dev \
  pkg-config \
  python3-dev \
  python3-pip \
  python3-venv

python3 -m venv /opt/pv-venv
/opt/pv-venv/bin/pip install --upgrade pip
/opt/pv-venv/bin/pip install --no-cache-dir "cmake==4.2.3" ninja uv
cat >/etc/profile.d/pv-venv.sh <<'PROFILE'
export PATH="/opt/pv-venv/bin:${PATH}"
PROFILE

rm -rf /var/lib/apt/lists/*
EOF

RUN <<'EOF'
set -eux

mkdir -p "$(dirname "${RAT_JAR}")"
curl --fail --location --silent --show-error \
  --output "${RAT_JAR}" \
  "https://repo.maven.apache.org/maven2/org/apache/rat/apache-rat/${RAT_VERSION}/apache-rat-${RAT_VERSION}.jar"
echo "${RAT_SHA256}  ${RAT_JAR}" | sha256sum --check
EOF

FROM dev-base AS deps-builder

RUN <<'EOF'
set -eux

apt-get update
apt-get install -y --no-install-recommends \
  autoconf \
  automake \
  libtool \
  make \
  perl
rm -rf /var/lib/apt/lists/*
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
