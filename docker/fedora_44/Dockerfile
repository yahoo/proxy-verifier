#
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM registry.fedoraproject.org/fedora:44 AS dev

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG RAT_VERSION=0.17
ARG RAT_SHA256=401939ebe5a52c6ed524029897bf914eaaba503d36c069ebcdbd8847a9e7cf93

ENV PATH="/opt/pv-venv/bin:${PATH}" \
    RAT_JAR="/opt/apache-rat/apache-rat-${RAT_VERSION}.jar"

RUN <<'EOF'
set -eux

dnf install -y \
  bzip2 \
  ca-certificates \
  curl \
  diffutils \
  gcc \
  gcc-c++ \
  git \
  java-25-openjdk-headless \
  libffi-devel \
  libnghttp2-devel \
  libnghttp3-devel \
  liburing-devel \
  openssl-devel \
  pkgconf-pkg-config \
  procps-ng \
  python3 \
  python3-devel \
  python3-pip \
  which

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

dnf clean all
rm -rf /var/cache/libdnf5
EOF

WORKDIR /workspace
