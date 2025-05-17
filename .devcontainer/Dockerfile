FROM ubuntu:22.04

# 设置工作目录
SHELL [ "bash", "-c" ]
ENV DEBIAN_FRONTEND=noninteractive
# ENV NVIDIA_VISIBLE_DEVICES all
# ENV NVIDIA_DRIVER_CAPABILITIES alls
WORKDIR /workspace

# 使用国内镜像源以加速下载
RUN sed -i 's@archive.ubuntu.com@mirrors.tuna.tsinghua.edu.cn@g' /etc/apt/sources.list && \
    sed -i 's@security.ubuntu.com@mirrors.tuna.tsinghua.edu.cn@g' /etc/apt/sources.list

# 更新并安装基础工具
RUN apt update && \
    apt install -yq \
        ffmpeg \
        dkms \
        build-essential \
        jq \
        tree \
        tldr \
        wget \
        curl \
        git \
        sudo \
        locales \
        net-tools \
        netcat \
        software-properties-common \
        vim

# 配置语言环境
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# 安装 X11 核心组件（比完整桌面环境更轻量）
RUN apt install -y \
    xserver-xorg \
    xauth \
    x11-apps \
    dbus-x11 \
    mesa-utils \
    xdg-utils \
    xterm \
    xvfb \
    xdotool \
    scrot \
    imagemagick

# 安装 Xfce4 轻量级桌面环境
RUN apt install -y \
    xubuntu-desktop
#     xfce4 \
#     xfce4-terminal \
#     thunar \
#     xfce4-panel \
#     xfce4-settings \
#     xfce4-session \
#     xfwm4 \
#     xfdesktop4 \
#     lightdm \
#     xfce4-goodies \
#     elementary-xfce-icon-theme

# # 安装 NVIDIA 驱动和库（使用通配符以适应不同系统）
# RUN apt update && \
#     apt install -y \
#     nvidia-driver-530 \
#     libnvidia-gl-530 \
#     nvidia-cuda-toolkit 
    
# 安装依赖
RUN apt update && apt install -y \
    libglu1-mesa \
    libxv1 \
    libxtst6 \
    libxrender1 \
    libssl-dev  \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libffi-dev \
    liblzma-dev \
    # USER apps
    # libreoffice \
    # firefox-esr \
    xpdf \
    gedit \
    xpaint \
    unzip \
    galculator
    

# Install noVNC 
RUN git clone --branch v1.5.0 https://ghfast.top/https://github.com/novnc/noVNC.git /opt/noVNC && \
    git clone --branch v0.12.0 https://ghfast.top/https://github.com/novnc/websockify /opt/noVNC/utils/websockify && \
    ln -s /opt/noVNC/vnc.html /opt/noVNC/index.html
# RUN wget https://github.com/VirtualGL/virtualgl/releases/download/3.1.2/virtualgl_3.1.2_amd64.deb
# RUN dpkg -i virtualgl_3.1.2_amd64.deb
# # RUN rm virtualgl_3.1.2_amd64.deb

RUN wget https://ghfast.top/https://github.com/TurboVNC/turbovnc/releases/download/3.1.4/turbovnc_3.1.4_amd64.deb
RUN dpkg -i turbovnc_3.1.4_amd64.deb
# RUN rm turbovnc_3.1.4_amd64.deb

# 添加用户并配置权限
RUN groupadd vglusers
RUN useradd -m agent
RUN usermod -aG sudo,video,vglusers agent
RUN echo 'agent:123' | chpasswd

# 配置 VirtualGL
# RUN mkdir -p /etc/opt/VirtualGL && \
#     echo "export VGL_DISPLAY=:0" > /etc/opt/VirtualGL/vgl_xauth_key && \
#     chmod 644 /etc/opt/VirtualGL/vgl_xauth_key 
    # /opt/VirtualGL/bin/vglserver_config -config +s +f -t

# 设置 TurboVNC 配置
# RUN echo "useVGL=true" >> /etc/turbovncserver.conf
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
RUN echo 'export DISPLAY=:4' >> ~/.bashrc && \
    echo 'export http_proxy=http://10.29.46.139:7890' >> ~/.bashrc && \
    echo 'export https_proxy=http://10.29.46.139:7890' >> ~/.bashrc && \
    echo 'export XDG_SESSION_TYPE=x11' >> ~/.bashrc && \
    echo 'export PATH=/opt/TurboVNC/bin:$PATH' >> ~/.bashrc && \
    echo 'export WIDTH=1024' >> ~/.bashrc && \
    echo 'export HEIGHT=768' >> ~/.bashrc
#     echo 'export DISPLAY=:1' >> ~/.bashrc && \
#     echo 'export VGL_DISPLAY=:0' >> ~/.bashrc && \
#     echo 'alias vglrun="/opt/VirtualGL/bin/vglrun"' >> ~/.bashrc


# 设置启动命令
USER agent

RUN mkdir /home/agent/.vnc/
RUN echo -e '#!/bin/sh\n \
xrdb "$HOME/.Xresources"\n \
xsetroot -solid grey\n \
export XKL_XMODMAP_DISABLE=1\n \
/etc/X11/Xsession\n \
unset SESSION_MANAGER\n \
unset DBUS_SESSION_BUS_ADDRESS\n \
x-session-manager & xfdesktop & xfce4-panel & xfce4-menu-plugin & xfsettingsd & xfconfd & xfwm4' > /home/agent/.vnc/xstartup && \
chmod +x /home/agent/.vnc/xstartup

# 在用户 agent 的上下文下继续构建（以下内容接在你的现有 Dockerfile 末尾）

# --- 安装 Conda 环境 ---
USER agent

COPY PC-Canary/requirements.txt /workspace/PC-Canary/requirements.txt
COPY computer-use-demo/computer_use_demo/requirements.txt /workspace/computer-use-demo/computer_use_demo/requirements.txt

WORKDIR /home/agent
# 2. 安装 Miniconda 到用户目录
RUN mkdir -p ~/miniconda3 && \
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/miniconda3/miniconda.sh && \
    bash ~/miniconda3/miniconda.sh -b -u -p ~/miniconda3 && \
    rm ~/miniconda3/miniconda.sh

# 3. 配置 Conda 环境变量（确保后续命令能识别 conda）
ENV PATH="/home/agent/miniconda3/bin:$PATH"
SHELL ["/bin/bash", "-c"]

# 4. 初始化 Conda 并创建环境
RUN conda init --all && \
    conda create -y -n agent-env python=3.11

WORKDIR /workspace
RUN pwd 
# 5. 在 Conda 环境中安装依赖
RUN conda run -n agent-env pip install --no-cache-dir \
    -r /workspace/PC-Canary/requirements.txt \
    -r /workspace/computer-use-demo/computer_use_demo/requirements.txt

# 6. 将 Conda 环境激活命令写入 .bashrc（可选）
RUN echo "conda activate agent-env" >> ~/.bashrc

# --- 恢复默认工作目录 ---
WORKDIR /workspace

#qbittorent环境依赖
# 在 root 用户下执行编译相关操作
USER root

COPY PC-Canary/apps/qBittorrent/boost_1_82_0 /tmp/boost_1_82_0
COPY PC-Canary/apps/qBittorrent/libtorrent-rasterbar-2.0.10 /tmp/libtorrent-rasterbar-2.0.10
COPY PC-Canary/apps/qBittorrent/qt-everywhere-src-6.5.3 /tmp/qt-everywhere-src-6.5.3

# 安装编译依赖（合并已有的APT安装操作）
RUN apt-get update && apt-get install -y \
    libssl-dev \
    zlib1g-dev \
    cmake \
    python3 \
    build-essential \
    pkg-config \
    automake \
    libtool \
    libboost-dev \
    libboost-system-dev \
    libssl-dev \
    zlib1g-dev \
    python3-dev \
    libqt6network6 \
    libgl1-mesa-dev \
    libxkbcommon-x11-dev \
    libxcb-cursor0 \
    libxcb1 \
    libxcb-glx0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-render0 \
    libxcb-shape0 \
    libxcb-shm0 \
    libxcb-sync1 \
    libxcb-util1 \
    libxcb-xfixes0 \
    libxcb-xinerama0 \
    libxkbcommon-x11-0
    
COPY PC-Canary/requirements.txt /workspace/PC-Canary/requirements.txt
COPY computer-use-demo/computer_use_demo/requirements.txt /workspace/computer-use-demo/computer_use_demo/requirements.txt

# 安装并编译 Boost 1.82
RUN cd /tmp/boost_1_82_0 && \
    ./bootstrap.sh --prefix=/usr/local && \
    ./b2 install && \
    rm -rf /tmp/boost_1_82_0

# 编译安装 libtorrent
RUN cd /tmp/libtorrent-rasterbar-2.0.10 && \
    rm -rf build && \
    # 创建全新构建目录
    mkdir build && \
    cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_STANDARD=17 \
        -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/libtorrent-rasterbar-2.0.10


RUN echo 'export PATH=/workspace/qt/qt/6.5.3/gcc_64/bin:$PATH' >> ~/.bashrc && \
    echo 'export LD_LIBRARY_PATH=/workspace/qt/qt/6.5.3/gcc_64/lib:$LD_LIBRARY_PATH' >> ~/.bashrc && \
    source ~/.bashrc
# 配置 pkg-config 路径
RUN echo '/usr/local/lib/pkgconfig' > /etc/ld.so.conf.d/local.conf && \
    ldconfig

# 验证安装
RUN pkg-config --modversion libtorrent-rasterbar

# 后续继续原有用户空间操作
USER agent
WORKDIR /workspace
