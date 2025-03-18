# That Monitor Guy: PC Agent基准测试评估器

基于触发器与开源用户软件的PC Agent基准测试评估系统，用于评估Agent执行桌面任务的能力。

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

## 安装

TODO 给出详细的安装方法
目前，本项目仅支持在Linux系统上运行，请使用Docker容器环境。
为运行本项目，目前需要：
1. 克隆本项目，安装相关依赖和库，配置并进入带 GUI 界面的 Docker 环境
2. 配置好 tdesktop 可执行文件，我已经自行编译了一个版本放在课题组服务器上，在其他环境中有可能需要重新编译（注意⚠️：编译 telegram 应用需要向官方申请 api key，我有一个已经申请好了的，可以找我要）
3. 我的 docker 环境内已经有了相关用户数据，如果重新配置可能需要一个测试用的 telegram 账号，可以找我要

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
