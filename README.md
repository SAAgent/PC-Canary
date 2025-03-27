# That Monitor Guy: PC Agent基准测试评估器

基于触发器监视与开源用户软件的PC Agent基准测试评估系统，用于评估Agent执行桌面任务的能力。

## 如何在Phoenix上运行
### 运行基本的VNC远程桌面环境
在 Phoenix 上已经有一个现成的镜像 monitor_env

(可选)也可以使用本项目的目录下的 Dockerfile 手动构建镜像
```bash
docker build \ 
  --build-arg HTTP_PROXY=YOUR_PROXY \
  --build-arg HTTPS_PROXY=YOUR_PROXY \
  -t monitor_env:latest \
  -f .devcontainer/Dockerfile .
```
run 这个镜像并进入容器环境中
```bash
docker run --rm -it --privileged   --network host -v /tmp/.X11-unix:/tmp/.X11-unix -v /YOUR_USER_ROOT/.Xauthority:/home/agent/.Xauthority monitor_env:latest                         
```
进入环境后，执行命令
```bash
vncserver 
```
以启动VNC桌面，根据你实际启动的桌面号（如:5）重设 DISPLAY 变量
```bash
export DISPLAY=:5
```
随后在你的 VNC Viewer 客户端上连接，以验证远程桌面服务是否启动，地址可能形如
```
vnc://10.109.246.210:5905
```
### 在远程桌面内运行 tdesktop 客户端
 TODO
## 功能特点

- 基于Frida钩子技术，无侵入式监控应用程序行为
- 异步评估模式，不干扰Agent正常执行
- 可扩展的任务注册机制
- 详细的评估报告生成
- 易于与任意结构的Agent系统集成

## 当前支持的任务

- **Telegram搜索任务**：评估Agent在Telegram客户端中搜索"news"的能力

## 系统要求

- Python 3.8+
- Frida 16.0.0+
- 相关依赖项（见requirements.txt）

## 使用方法

### 直接测试评估器

可以直接运行评估器，然后手动执行Telegram搜索操作：

```bash
python test_evaluator.py
```

参数说明：
- `--process`：目标进程名称（默认：Telegram）
- `--wait`：等待时间，单位为秒（默认：60）

### 与Agent系统集成

将评估器与Agent系统集成运行：

```bash
python run_agent_with_evaluator.py
```

参数说明：
- `--model`：使用的模型类型（openai、gemini或qwen，默认：openai）
- `--api_key`：API密钥（如果未提供则从环境变量获取）
- `--max_steps`：最大执行步骤数（默认：10）
- `--eval_wait`：评估器启动等待时间（秒，默认：5）

## 架构说明

整个评估系统由以下核心组件组成：

1. **核心评估器（BenchmarkEvaluator）**：负责Frida初始化、脚本加载以及结果收集
2. **任务评估器（如TelegramSearchEvaluator）**：实现特定任务的评估逻辑
3. **Frida钩子脚本**：监控目标应用程序，并向评估器发送事件
4. **集成模块**：与现有Agent系统的集成功能

## 自定义任务

要添加新的评估任务，需要：

1. 创建新的Frida钩子脚本（如evaluator/scripts/new_task_hooker.js）
2. 创建对应的任务评估器类（如evaluator/new_task.py）
3. 在集成模块中使用新任务

## 注意事项

- 需要确保Telegram应用已经启动
- Frida钩子脚本可能需要根据不同版本的Telegram客户端进行调整
- 建议使用 Docker 容器环境以复现评估结果

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
└── telegram_evaluator_test.py       # Telegram评估器测试脚本
```
