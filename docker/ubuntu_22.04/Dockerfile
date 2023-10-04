FROM ubuntu:22.04

# So that installing pkg-config does not interactively prompt during the image
# creation process.
ARG DEBIAN_FRONTEND=noninteractive

# Packages for building Proxy Verifier and its dependencies.
RUN apt-get update; \
    apt-get install -y \
        pipenv libssl-dev autoconf libtool pkg-config git curl sudo

# The apt version of pipenv is outdated and does not run. Upgrade to a recent
# version so it works.
RUN python3 -m pip install --upgrade pipenv

# Install the library dependencies in /opt.
WORKDIR /var/tmp
RUN \
    git clone https://github.com/yahoo/proxy-verifier.git; \
    cd proxy-verifier; \
    bash tools/build_library_dependencies.sh /opt
