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
        software-properties-common

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
RUN git clone --branch v1.5.0 https://github.com/novnc/noVNC.git /opt/noVNC && \
    git clone --branch v0.12.0 https://github.com/novnc/websockify /opt/noVNC/utils/websockify && \
    ln -s /opt/noVNC/vnc.html /opt/noVNC/index.html
# RUN wget https://github.com/VirtualGL/virtualgl/releases/download/3.1.2/virtualgl_3.1.2_amd64.deb
# RUN dpkg -i virtualgl_3.1.2_amd64.deb
# # RUN rm virtualgl_3.1.2_amd64.deb

RUN wget https://github.com/TurboVNC/turbovnc/releases/download/3.1.4/turbovnc_3.1.4_amd64.deb
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