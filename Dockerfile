FROM ubuntu:20.04

RUN apt-get update && \
apt-get install -y clang-9 llvm vim libelf-dev libpcap-dev python gcc-multilib build-essential make sudo linux-tools-$(uname -r) linux-tools-generic linux-tools-common

WORKDIR /ianchen

COPY libbpf ./libbpf

CMD [ "python", "main.py" ]