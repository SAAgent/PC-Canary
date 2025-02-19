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
RUN sudo apt install -yq \
        jq \
        tree \
        tldr


RUN sudo apt update
