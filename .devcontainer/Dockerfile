FROM nvidia/cuda:12.8.0-base-ubuntu22.04

# 设置工作目录
SHELL [ "bash", "-c" ]
ENV DEBIAN_FRONTEND=noninteractive
ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES all
WORKDIR /workspace

RUN sed -i 's@archive.ubuntu.com@mirrors.tuna.tsinghua.edu.cn@g' /etc/apt/sources.list && \
    sed -i 's@security.ubuntu.com@mirrors.tuna.tsinghua.edu.cn@g' /etc/apt/sources.list

# update apt and install packages
RUN apt update && \
    apt install -yq \
        ffmpeg \
        dkms \
        build-essential

# add user tools
RUN apt install -yq \
        jq \
        tree \
        tldr

RUN apt update

RUN apt install -y tightvncserver xfce4
RUN apt-get install -y sudo

# 添加用户到 sudo 组 
RUN useradd -m agent
RUN usermod -aG sudo agent
RUN echo 'agent:123' | chpasswd
USER agent
ENV USER=agent
SHELL [ "bash", "-c" ]

RUN echo 'export http_proxy="http://127.0.0.1:7890"' >> ~/.bashrc && \
    echo 'export https_proxy="http://127.0.0.1:7890"' >> ~/.bashrc
