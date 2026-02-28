# 1. 基础镜像：Ubuntu 20.04
FROM ubuntu:20.04

# 避免交互式安装时的时区选择卡顿
ENV DEBIAN_FRONTEND=noninteractive

# 2. 安装构建依赖 (包含 afl)
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libsqlite3-dev \
    python3 \
    python3-pip \
    afl++ \
    && rm -rf /var/lib/apt/lists/*

# 3. 定义版本参数
ARG NANOMQ_COMMIT=2d80f7cff59fab51ec1b7bfe478e3860af91fc39

# 4. 拉取代码
WORKDIR /usr/local/src
RUN git clone https://github.com/emqx/nanomq.git \
    && cd nanomq \
    && git checkout ${NANOMQ_COMMIT} \
    && git submodule update --init --recursive

# 5. 设置编译器为 afl-gcc
ENV CC=afl-gcc
ENV CXX=afl-g++

# 6. 编译 NanoMQ (Debug + ASAN)
WORKDIR /usr/local/src/nanomq
RUN mkdir build && cd build \
    && cmake -DDEBUG=1 -DASAN=1 -DBUILD_STATIC=OFF .. \
    && make -j$(nproc)

# 7. 【关键修改】复制本地配置文件到镜像内的 /etc 目录
# 注意：构建时，你的宿主机当前目录下必须有 nanomq.conf 文件
COPY nanomq.conf /etc/nanomq.conf

# 8. 【关键修改】修正工作目录
# 二进制文件实际位于 build/nanomq 目录下，所以我们需要进入这一层
WORKDIR /usr/local/src/nanomq/build/nanomq

# 配置 ASan 选项
ENV ASAN_OPTIONS=symbolize=1:detect_leaks=1:halt_on_error=0

# 启动命令
# 现在我们已经在正确的目录下，可以直接 ./nanomq
# 并且配置文件指向了我们刚 COPY 进去的 /etc/nanomq.conf
CMD ["./nanomq", "start", "--conf", "/etc/nanomq.conf"]
