#!/bin/bash

# 配置conda环境
source ~/miniconda3/bin/activate
conda create -y -n agent-env python=3.11
conda activate agent-env

# 安装依赖包
pip install -r /workspace/PC-Canary/requirements.txt

# 添加自动激活到bashrc
echo 'conda activate agent-env' >> ~/.bashrc

echo "Conda环境配置完成！"

# sudo chown -R agent:agent /apps/tdesktop/Debug/
# sudo cp -r /apps/tdesktop/Debug/tdata /apps/tdesktop/Debug/
# sudo chown -R agent:agent /apps/tdesktop/Debug/tdata
