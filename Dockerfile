FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y clang llvm vim libelf-dev \
    libpcap-dev gcc-multilib build-essential make sudo
RUN apt-get install -y linux-tools-$(uname -r) linux-tools-common linux-tools-generic

WORKDIR /ianchen

COPY libbpf ./libbpf
CMD ["/bin/bash"]