# Agent benchmark 系统配置文档


## 项目概述

本项目是一个基于AI Agent的自动化Benchmark系统，旨在基于对开源 PC APP 进行准确轻量的自动化测试。
目前本项目能够实现：
- 接入基于 Prompt Engineering 的 Agent 框架，兼容 OpenAI 的 API 接口
- 基于代码的 GUI 环境控制，使用 pyautogui 模拟鼠标键盘操作
- 基于 docker 的跨平台支持和轻量级部署



## 环境配置

### docker 环境搭建

本项目可以使用 vscode 的 devcontainer 功能，快速配置开发环境。可以通过相关文件夹的Dockerfile 和 devcontainer.json 文件配置容器。
具体来说，目前实现的容器基于 ubuntu 22.04 系统，并安装了 X11 和 Xfce4 桌面环境，支持 GPU 计算，通过 TightVNC 提供远程图形化界面访问。

在进入项目后，配置`DISPLAY`环境变量，启动 VNC 服务器后，即可在 VNC 桌面上启动相关应用。

### 可用应用

本项目目前支持的可用应用包括：
- Telegram
- Mailspring
- Markdown
- YesPlayMusic
- mpv

在克隆时，使用命令：
```bash
git submodule update --init --recursive
```
可克隆应用的源代码。选择需要测试的应用自行编译即可。
一些应用需要自行安装编译所需的相关依赖（如 nodejs 和 python 环境）。
有一份`requirements.txt`文件供参考实际安装的依赖。

## 项目结构

### 主要模块

#### agent模块
负责AI代理的核心逻辑：
- `base_agent.py`：基础代理类，处理观察和决策
- `prompt.py`：提示词模板
- `models/`：不同AI模型的接口实现（OpenAI、Gemini等）

#### env模块
环境控制器：
- `controller/code_execution_controller.py`：代码执行控制器
- `controller/gui_controll_interface.py`：GUI控制接口

#### utils模块
工具函数和辅助类：
- `logger.py`：日志系统，记录执行过程和结果
- `__init__.py`：模块导出

#### apps模块
测试应用程序（作为Git子模块）：
- `Mailspring`：邮件客户端
- `tdesktop`：Telegram桌面客户端
- `marktext`：Markdown编辑器
- `YesPlayMusic`：音乐播放器
- `mpv`：视频播放器

### 主文件

- `run_agent.py`：主程序，运行代理测试
- `README.md`：项目说明


## 开发指南

### 添加新测试

1. 在`tests/tasks/`目录下创建新的测试任务
2. 在`tests/`目录下创建对应的测试脚本

### 添加新应用

将应用添加为Git子模块：
   ```bash
   git submodule add https://github.com/username/repo apps/app_name
   ```

### 扩展代理功能

1. 基于`agent/base_agent.py`修改并添加新功能
2. 在`agent/prompt.py`中更新提示词模板
3. 如需支持新的AI模型，在`agent/models/`目录下添加对应实现

## TODO

- 支持全新的 evaluator
- 支持更多应用
- 支持更多 Agent
- 添加更多任务
- 支持远程桌面的硬件加速
- 添加更多文档
- 已知 BUG：Mailsping 软件的桌面密钥软件不兼容，官方文档无效。[详情](https://community.getmailspring.com/t/password-management-error/199/2)
- 已知 BUG：tightvnc 与 xdotool 冲突