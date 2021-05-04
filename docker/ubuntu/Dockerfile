FROM ubuntu:20.04

# So that installing pkg-config does not interactively prompt during the image
# creation process.
ARG DEBIAN_FRONTEND=noninteractive

# Packages for building Proxy Verifier and its dependencies.
RUN apt-get update; \
    apt-get install -y pipenv autoconf libtool pkg-config

# Install the library dependencies in /opt.
WORKDIR /var/tmp
RUN \
    git clone git@github.com:yahoo/proxy-verifier.git; \
    cd proxy-verifier; \
    bash tools/build_http3_dependencies.sh /opt
