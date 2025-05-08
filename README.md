# PC-Canary: PC Agent基准测试评估器

基于触发器监视与开源用户软件的PC Agent基准测试评估系统，用于评估Agent执行桌面任务的能力。

## 功能特点

- 无侵入式监控应用程序行为，无需无障碍应用权限
- 异步评估模式，不干扰Agent正常执行
- 可扩展的任务注册机制
- 详细的评估报告生成
- 易于与任意结构的Agent系统集成

## 当前支持的任务

- **Telegram搜索任务**：评估Agent在Telegram客户端中搜索"news"的能力
## 运行
### 配置 VNC 远程桌面环境
克隆本仓库
```bash
git clone https://github.com/k0zhevnikov/image_setup
```
并使用本项目目录下的 Dockerfile 手动构建镜像
```bash
docker build \ 
  --build-arg HTTP_PROXY=YOUR_PROXY \
  --build-arg HTTPS_PROXY=YOUR_PROXY \
  -t monitor_env:cpu \
  -f .devcontainer/Dockerfile .
```
run 这个镜像并进入容器环境中
```bash
docker run --rm -it \
  --privileged \
  --network host \
  monitor_env:cpu                         
```
进入环境后，执行命令
```bash
vncserver -xstartup /home/agent/.vnc/xstartup  -geometry  1024x768 :=5
```
以启动VNC桌面，根据你实际启动的桌面号（如:5）重设 DISPLAY 变量
```bash
export DISPLAY=:5
```
随后在你的 VNC Viewer 客户端上连接，以验证远程桌面服务是否启动，地址可能形如
```
vnc://YOUR_SERVER_IP:5905
```
### 在远程桌面内运行 tdesktop 客户端
本项目将 tdesktop 的源代码仓库作为自己的一个子模块，首先需要初始化它
```bash
git submodule update --init --recursive tdesktop
```
#### （可选）自行编译并配置得到 tdesktop 客户端和用户数据
对于项目开发者，建议进入 `apps/tdesktop` 目录，参考官方文档自行编译并配置得到 Debug 模式的 tdesktop 客户端。

编译完成后，可执行文件与用户数据会被安装到`apps/tdesktop/out/Debug` 目录下。大体来说包括
```bash
Debug/
├── tdata # 用户数据目录
│   └── ...
├── DebugLogs # 所有运行日志的总目录
│   └── ...
├── Telegram # Linux 系统下可执行文件
└── log.txt # 运行日志
```
建议在编译完成后，在 GUI 环境下手动配置好用户数据，如进行账户登录等操作。
#### 配置容器以保存用户数据状态
新建一个 docker 数据卷，拷贝 `tdata` 目录中的内容到挂载卷中，操作类似于
```bash
docker volume create telegram-data2
docker run --rm -it \
  monitor_env:cpu
  -v telegram-data2:/dest
  -v ${localWorkspaceFolder}/apps/tdesktop/out/Debug:/src
```
```bash
# 在容器中执行
cp -r /src/tdata /dest/
exit
```

随后，将 `tdata` 数据卷以 volume 模式挂载到容器中，并将 `Telegram` 文件以 bind 模式挂载到容器中。同时，出于状态保存与恢复的考虑，对数据卷应该做额外的备份。

最后的`tdata`文件夹应该与可执行文件在同一目录下，并确保容器用户有权限读写。可以参考 `.devcontainer/devcontainer.json` 文件的相关配置。
```json
{
    "mounts": [
        "source=${localWorkspaceFolder},target=/workspace,type=bind",
        "source=telegram-data2,target=/apps/tdesktop/Debug,type=volume",
        "source=${localWorkspaceFolder}/apps/tdesktop/out/Debug/Telegram,target=/apps/tdesktop/Debug/Telegram,type=bind"
    ],
    "postCreateCommand": "bash ./.devcontainer/postCreateCommand.sh",
}
```
```bash
#  postCreateCommand.sh，请确保指令被运行
#!/bin/bash
sudo chown -R agent:agent /apps/tdesktop/Debug/
```
配置完成后，重新生成容器并进入环境，运行 `/apps/tdesktop/Debug/Telegram` 客户端，验证是否已经自带用户数据。若已经自带，则基本环境配置完成。

### 评估器

可以直接运行`test_evaluator.py`和`run_evaluator.py`，然后手动在 GUI 环境内操作Telegram 客户端，点击搜索栏输入搜索内容，观察是否能在正确输入时触发 evaluator 回调：

```bash
python test_evaluator.py
```

### 与Agent系统集成

目前本项目有一个基本的 prompt-based 的 GUI Agent， 可以测试将评估器与Agent系统集成运行：

```bash
python run_agent_with_evaluator.py
```

## 架构说明

整个评估系统由以下核心组件组成：

```bash
project/                         # 项目根目录
├── agent/                           # 代理系统模块
│   ├── models/                      
│   ├── base_agent.py                # 代理基类，基本的 prompt Agent实现
│   └── prompt.py                    # 提示词生成和管理模块
│
├── apps/                            # 目标应用程序仓库
│   ├── tdesktop/                    # Telegram Desktop应用
│   ├── ...
│
├── env/                             
│   └── controller/                  # 环境控制器，管理为 Agent 暴露出来的交互接口
│       └── code_execution_controller.py  # 代码执行接口，为 Agent 提供代码执行能力
│
├── evaluator/                       # 评估系统，负责评估代理性能
│   ├── core/                        # 评估器核心组件
│   │   ├── base_evaluator.py        # 评估器基类，定义基本评估流程
│   │   ├── hook_manager.py          # 钩子管理器，负责Frida脚本管理
│   │   └── result_collector.py      # 结果收集器，负责保存评估数据
│   │
│   └── utils/                       # 日志工具
│
├── tests/                           
│   └── tasks/                       # 任务测试目录
│       └── telegram/                # Telegram APP下的所有任务
│           └── task01_search/       # Telegram搜索功能测试
│               ├── handler.py       # 事件处理器，处理钩子脚本事件
│               ├── hooker.js        # Frida钩子脚本，用于监控Telegram
│               └── config.json      # 任务配置文件，定义测试参数
│
├── utils/                           # 通用工具库
│   └── logger.py                    # 日志记录模块
│
├── run_agent_with_evaluator.py       # 测试脚本
│
├── test_evaluator.py       # 测试脚本
│
├── run_evaluator.py       # 运行评估器
│
└── README.md       # 说明文档
```