#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

FROM docker.io/rockylinux/rockylinux:9 AS pv-libs-builder-base

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
  python3.11 \
  python3.11-devel \
  python3.11-pip

ln -sf /usr/bin/python3.11 /usr/local/bin/python3
ln -sf /usr/bin/python3.11-config /usr/local/bin/python3-config
python3.11 -m venv /opt/pv-venv
/opt/pv-venv/bin/pip install --upgrade pip
/opt/pv-venv/bin/pip install --no-cache-dir "cmake==4.2.3" ninja uv

dnf clean all
rm -rf /var/cache/dnf
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
FROM docker.io/rockylinux/rockylinux:9 AS dev

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
  python3.11 \
  python3.11-devel \
  python3.11-pip

ln -sf /usr/bin/python3.11 /usr/local/bin/python3
ln -sf /usr/bin/python3.11-config /usr/local/bin/python3-config
python3.11 -m venv /opt/pv-venv
/opt/pv-venv/bin/pip install --upgrade pip
/opt/pv-venv/bin/pip install --no-cache-dir "cmake==4.2.3" ninja uv

dnf clean all
rm -rf /var/cache/dnf
EOF

COPY --from=pv-libs-builder /opt/pv_libs /opt/pv_libs

WORKDIR /workspace
