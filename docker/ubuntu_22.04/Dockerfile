FROM ubuntu:22.04

# So that installing pkg-config does not interactively prompt during the image
# creation process.
ARG DEBIAN_FRONTEND=noninteractive

# Packages for building Proxy Verifier and its dependencies.
RUN apt-get update; \
    apt-get install -y \
        python3-pip libssl-dev autoconf automake libtool pkg-config git curl sudo make
RUN python3 -m pip install "cmake==4.2.3" ninja uv

# Install the library dependencies in /opt.
WORKDIR /var/tmp
RUN \
    git clone https://github.com/yahoo/proxy-verifier.git; \
    cd proxy-verifier; \
    bash tools/build_library_dependencies.sh /opt
