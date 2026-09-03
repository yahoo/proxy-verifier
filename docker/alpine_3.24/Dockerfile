#
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM docker.io/library/alpine:3.24 AS dev

ARG RAT_VERSION=0.17
ARG RAT_SHA256=401939ebe5a52c6ed524029897bf914eaaba503d36c069ebcdbd8847a9e7cf93

ENV PATH="/opt/pv-venv/bin:${PATH}" \
    RAT_JAR="/opt/apache-rat/apache-rat-${RAT_VERSION}.jar"

RUN apk add --no-cache \
  bash \
  bzip2 \
  build-base \
  ca-certificates \
  coreutils \
  curl \
  diffutils \
  gcompat \
  git \
  libffi-dev \
  liburing-dev \
  linux-headers \
  nghttp2-dev \
  nghttp2-static \
  nghttp3-dev \
  nghttp3-static \
  openjdk21-jre-headless \
  openssl-dev \
  openssl-libs-static \
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
mkdir -p "$(dirname "${RAT_JAR}")"
curl --fail --location --silent --show-error \
  --output "${RAT_JAR}" \
  "https://repo.maven.apache.org/maven2/org/apache/rat/apache-rat/${RAT_VERSION}/apache-rat-${RAT_VERSION}.jar"
echo "${RAT_SHA256}  ${RAT_JAR}" | sha256sum --check
cat >/etc/profile.d/pv-venv.sh <<'PROFILE'
export PATH="/opt/pv-venv/bin:${PATH}"
PROFILE
EOF

WORKDIR /workspace
