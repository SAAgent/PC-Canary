FROM ghcr.io/selkies-project/nvidia-egl-desktop:22.04

# 添加构建参数，默认值为1000（如果没有提供）
ARG USER_UID=1000
ARG USER_GID=1000

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
    xterm \
    scrot \
    imagemagick

# 安装依赖
RUN apt update && apt install -y --fix-missing \
    xpdf \
    gedit \
    xpaint \
    unzip \
    galculator

# 添加用户到sudo组并设置密码
RUN usermod -aG sudo ubuntu
RUN echo 'ubuntu:123' | chpasswd

# 创建新用户agent
RUN groupadd -g ${USER_GID} agent || groupmod -g ${USER_GID} agent
RUN useradd -u ${USER_UID} -g ${USER_GID} -m -s /bin/bash agent || usermod -u ${USER_UID} -g ${USER_GID} agent
RUN echo 'agent:123' | chpasswd

# 配置agent用户权限
RUN usermod -aG sudo agent
RUN echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
RUN echo "agent ALL=(ubuntu) NOPASSWD:ALL" >> /etc/sudoers

# 让agent能访问ubuntu的home目录
RUN usermod -aG ubuntu agent
RUN chmod -R g+rwx /home/ubuntu

# 为agent用户安装miniconda
USER agent
WORKDIR /home/agent
ENV USER=agent
ENV HOME=/home/agent

# 安装和配置 Miniconda
RUN mkdir -p ~/miniconda3 && \
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /home/agent/miniconda3/miniconda.sh && \
    bash /home/agent/miniconda3/miniconda.sh -b -u -p /home/agent/miniconda3 && \
    rm /home/agent/miniconda3/miniconda.sh && \
    /home/agent/miniconda3/bin/conda init --all

# 配置环境变量
RUN echo 'export http_proxy=http://10.29.46.139:7890' >> /home/agent/.bashrc && \
    echo 'export https_proxy=http://10.29.46.139:7890' >> /home/agent/.bashrc

# 切换回ubuntu用户运行supervisord
USER 1000
ENV SHELL=/bin/bash
ENV USER=ubuntu
WORKDIR /home/ubuntu

EXPOSE 8080

ENTRYPOINT ["/usr/bin/supervisord"]
