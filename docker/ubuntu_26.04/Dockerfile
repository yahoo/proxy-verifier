#
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM docker.io/library/ubuntu:26.04 AS dev

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG DEBIAN_FRONTEND=noninteractive
ARG RAT_VERSION=0.17
ARG RAT_SHA256=401939ebe5a52c6ed524029897bf914eaaba503d36c069ebcdbd8847a9e7cf93

ENV PATH="/opt/pv-venv/bin:${PATH}" \
    RAT_JAR="/opt/apache-rat/apache-rat-${RAT_VERSION}.jar"

RUN <<'EOF'
set -eux

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  default-jre-headless \
  diffutils \
  g++ \
  gcc \
  git \
  libc6-dev \
  libffi-dev \
  libnghttp2-dev \
  libnghttp3-dev \
  libssl-dev \
  lbzip2 \
  pkg-config \
  procps \
  python3-dev \
  python3-pip \
  python3-venv

python3 -m venv /opt/pv-venv
/opt/pv-venv/bin/pip install --upgrade pip
/opt/pv-venv/bin/pip install --no-cache-dir "cmake==4.2.3" ninja uv
mkdir -p "$(dirname "${RAT_JAR}")"
curl --fail --location --silent --show-error \
  --output "${RAT_JAR}" \
  "https://repo.maven.apache.org/maven2/org/apache/rat/apache-rat/${RAT_VERSION}/apache-rat-${RAT_VERSION}.jar"
echo "${RAT_SHA256}  ${RAT_JAR}" | sha256sum --check
cat >/etc/profile.d/pv-venv.sh <<'PROFILE'
export PATH="/opt/pv-venv/bin:${PATH}"
PROFILE

rm -rf /var/lib/apt/lists/*
EOF

WORKDIR /workspace
