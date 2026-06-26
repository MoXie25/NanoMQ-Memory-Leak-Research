FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    binutils \
    net-tools \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

ARG NANOMQ_COMMIT=2d80f7cff59fab51ec1b7bfe478e3860af91fc39

WORKDIR /usr/local/src

RUN git clone https://github.com/emqx/nanomq.git \
    && cd nanomq \
    && git checkout ${NANOMQ_COMMIT} \
    && git submodule update --init --recursive

WORKDIR /usr/local/src/nanomq

RUN mkdir build && cd build \
    && cmake -DDEBUG=1 -DASAN=1 -DBUILD_STATIC=OFF .. \
    && make -j$(nproc)

COPY nanomq.conf /etc/nanomq.conf
COPY 249exploit_leak.py /tmp/249exploit_leak.py

WORKDIR /usr/local/src/nanomq/build/nanomq

ENV ASAN_OPTIONS=symbolize=1:detect_leaks=1:halt_on_error=0

# 不设置 CMD，方便手动启动和观察 ASAN 日志
