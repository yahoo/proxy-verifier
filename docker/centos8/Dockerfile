FROM centos:8

# Packages for building Proxy Verifier and its dependencies.
RUN yum -y update; \
    yum install -y python38-pip git
RUN dnf -y group install "Development Tools"
RUN pip3 install pipenv

# Install the library dependencies in /opt.
WORKDIR /var/tmp
RUN \
    git clone https://github.com/yahoo/proxy-verifier.git; \
    cd proxy-verifier; \
    bash tools/build_library_dependencies.sh /opt
