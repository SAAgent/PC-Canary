FROM ghcr.io/selkies-project/nvidia-egl-desktop:22.04

# 设置工作目录
SHELL [ "bash", "-c" ]
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /workspace

# 使用国内镜像源以加速下载
RUN sed -i 's@archive.ubuntu.com@mirrors.tuna.tsinghua.edu.cn@g' /etc/apt/sources.list && \
    sed -i 's@security.ubuntu.com@mirrors.tuna.tsinghua.edu.cn@g' /etc/apt/sources.list

USER root

# 更新并安装基础工具
RUN apt update && \
    apt install -yq \
        ffmpeg \
        build-essential \
        jq \
        tree \
        tldr \
        wget \
        curl \
        git \
        sudo \
        locales \
        # net-tools \
        # netcat \
        software-properties-common

# 配置语言环境
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# 安装 X11 核心组件
RUN apt install -y \
    # xserver-xorg \
    # xauth \
    # x11-apps \
    # dbus-x11 \
    # mesa-utils \
    # xdg-utils \
    xterm \
    # xvfb \
    # xdotool \
    scrot \
    imagemagick

# 安装依赖
RUN apt update && apt install -y --fix-missing \
    # libglu1-mesa \
    # libxv1 \
    # libxtst6 \
    # libxrender1 \
    # libssl-dev  \
    # zlib1g-dev \
    # libbz2-dev \
    # libreadline-dev \
    # libsqlite3-dev \
    # libncursesw5-dev \
    # xz-utils \
    # tk-dev \
    # libxml2-dev \
    # libxmlsec1-dev \
    # libffi-dev \
    # liblzma-dev \
    xpdf \
    gedit \
    xpaint \
    unzip \
    galculator

# 添加用户并配置权限
RUN useradd -m agent
RUN usermod -aG sudo agent && usermod -aG sudo ubuntu
RUN echo 'agent:123' | chpasswd

# 配置环境变量
USER agent
ENV USER=agent
SHELL [ "bash", "-c" ]

# 安装和配置 Miniconda
RUN mkdir -p ~/miniconda3 && \
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/miniconda3/miniconda.sh && \
    bash ~/miniconda3/miniconda.sh -b -u -p ~/miniconda3 && \
    rm ~/miniconda3/miniconda.sh && \
    ~/miniconda3/bin/conda init --all

# 配置环境变量
RUN echo 'export http_proxy=http://10.29.46.139:7890' >> /home/agent/.bashrc && \
    echo 'export https_proxy=http://10.29.46.139:7890' >> /home/agent/.bashrc

# # 设置启动命令
USER ubuntu
