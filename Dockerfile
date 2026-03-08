FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    clang \
    cmake \
    git \
    ninja-build \
    pkg-config \
    build-essential \
    libboost-all-dev \
    llvm-15 \
    llvm-15-dev \
    libmd-dev \
    libssl-dev \
    qemu-user \
    gcc-riscv64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["/bin/bash"]
