#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
通用评估器运行脚本
可用于运行任何定义在tests/tasks目录下的应用评估任务

使用方法：
python run_evaluator.py --app telegram --task task01_search --app-path /path/to/app [--custom-params '{"query":"news"}']
"""

import os
import sys
import time
import json
import argparse
import signal
from typing import Dict, Any, Optional

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(PROJECT_ROOT)

from evaluator.core.base_evaluator import BaseEvaluator, CallbackEventData

# Global flag to signal loop termination from callback
evaluation_finished = False

# 信号处理函数
def signal_handler(sig, frame, evaluator=None):
    """
    处理CTRL+C信号

    Args:
        sig: 信号类型
        frame: 栈帧
        evaluator: 评估器实例
    """
    print("\n\n用户中断评估...")

    if evaluator and evaluator.is_running:
        print("正在停止评估器...")
        evaluator.stop()
        evaluator.stop_app()
    sys.exit(0)


def handle_evaluator_event(event_data: CallbackEventData, evaluator: BaseEvaluator):
    """
    处理评估器事件的回调函数

    Args:
        event_data: 事件数据
        evaluator: 评估器实例
    """
    print(f"\n收到评估器事件: {event_data.event_type} - {event_data.message}")

    # Use the global flag to signal termination
    global evaluation_finished

    if event_data.event_type == "task_completed": # Check string event type from CallbackEventData
        print(f"任务成功完成")
        evaluation_finished = True # Signal the main loop to stop
        # evaluator.stop() # <- Removed: stop() is called after the loop
        # print("任务完成，正在停止评估器...") # <- Message moved after loop

    elif event_data.event_type == "task_error":
        print(f"任务出错")
        evaluation_finished = True # Signal the main loop to stop

    elif event_data.event_type == "evaluator_stopped": # This might still be triggered by BaseEvaluator.stop() if needed
        print(f"评估器已停止")
        # evaluation_finished = True # Decide if external stop should also terminate the loop immediately


def print_app_instructions(app: str, task: str, instruction: str):
    """
    打印特定应用和任务的操作指南

    Args:
        app: 应用名称
        task: 任务ID
        instruction: 任务指令
    """
    print("\n" + "=" * 60)
    print(f"{app.capitalize()}评估器运行中...")
    print(f"任务: {task}")
    print(f"任务指令: {instruction}")
    print("\n请按照以下步骤操作：")
    print("1. 应用将会自动启动（如果提供了路径）")
    print("2. 请根据上述任务指令操作应用")
    print("3. 评估器会自动监测您的操作")
    print("4. 任务完成后会自动通知")
    print("5. 随时可按CTRL+C终止评估")
    print("=" * 60 + "\n")


def load_config(app: str, task: str) -> Optional[Dict]:
    """
    加载指定应用和任务的配置文件

    Args:
        app: 应用名称
        task: 任务ID

    Returns:
        Dict: 配置文件内容，如果无法加载则返回None
    """
    config_path = os.path.join(PROJECT_ROOT, "tests", "tasks", app, task, "config.json")
    if not os.path.exists(config_path):
        print(f"错误: 配置文件不存在: {config_path}")
        return None

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"错误: 无法加载配置文件: {str(e)}")
        return None


def parse_custom_params(params_str: str) -> Dict:
    """
    解析自定义参数字符串为字典

    Args:
        params_str: JSON格式的参数字符串

    Returns:
        Dict: 解析后的参数字典
    """
    if not params_str:
        return {}

    try:
        return json.loads(params_str)
    except json.JSONDecodeError as e:
        print(f"警告: 自定义参数解析失败: {str(e)}")
        print("将使用空参数字典")
        return {}


def list_available_tasks():
    """
    列出所有可用的应用和任务
    """
    tasks_dir = os.path.join(PROJECT_ROOT, "tests", "tasks")
    if not os.path.exists(tasks_dir):
        print("错误: 任务目录不存在")
        return

    print("\n可用的应用和任务:")
    print("=" * 60)

    for app in os.listdir(tasks_dir):
        app_dir = os.path.join(tasks_dir, app)
        if not os.path.isdir(app_dir):
            continue

        print(f"应用: {app}")
        for task in os.listdir(app_dir):
            task_dir = os.path.join(app_dir, task)
            if not os.path.isdir(task_dir):
                continue

            config_path = os.path.join(task_dir, "config.json")
            task_desc = ""
            if os.path.exists(config_path):
                try:
                    with open(config_path, "r", encoding="utf-8") as f:
                        config = json.load(f)
                        task_desc = config.get("description", "")
                except:
                    pass

            print(f"  - 任务: {task} {task_desc}")

        print("-" * 60)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="通用评估器运行脚本")
    parser.add_argument("--app", type=str, help="要评估的应用名称")
    parser.add_argument("--task", type=str, help="要运行的任务ID")
    parser.add_argument("--app-path", type=str, help="应用可执行文件路径")
    parser.add_argument(
        "--log-dir", type=str, default="logs", help="日志目录 (默认: logs)"
    )
    parser.add_argument(
        "--timeout", type=int, default=300, help="超时时间，秒 (默认: 300)"
    )
    parser.add_argument("--custom-params", type=str, help="自定义参数，JSON格式字符串")
    parser.add_argument("--list", action="store_true", help="列出所有可用的应用和任务")

    args = parser.parse_args()

    # 如果使用--list参数，则列出可用任务后退出
    if args.list:
        list_available_tasks()
        return 0

    # 检查必要参数
    if not args.app or not args.task:
        print("错误: 必须指定应用名称(--app)和任务ID(--task)")
        parser.print_help()
        return 1

    # 检查任务目录是否存在
    task_path = os.path.join(PROJECT_ROOT, "tests", "tasks", args.app, args.task)
    if not os.path.exists(task_path):
        print(f"错误: 任务目录不存在: {task_path}")
        return 1

    # 加载任务配置
    config = load_config(args.app, args.task)
    if not config:
        return 1

    # 应用路径处理
    app_path = args.app_path
    if not app_path and "application_info" in config:
        app_path = config["application_info"].get("executable_path")

    if app_path and not os.path.exists(app_path):
        print(f"警告: 应用可执行文件不存在: {app_path}")
        user_choice = input("是否继续评估？(y/n): ").strip().lower()
        if user_choice != "y":
            return 0
        app_path = None  # 如果文件不存在但用户选择继续，则将路径置为None

    # 解析自定义参数
    custom_params = parse_custom_params(args.custom_params)

    # 创建日志目录
    log_dir = args.log_dir
    os.makedirs(log_dir, exist_ok=True)

    # 任务信息
    task = {
        "category": args.app,
        "id": args.task,
    }

    print(f"初始化评估器...")
    print(f"应用: {args.app}")
    print(f"任务: {args.task}")
    if app_path:
        print(f"应用路径: {app_path}")
    if custom_params:
        print(f"自定义参数: {json.dumps(custom_params, ensure_ascii=False)}")

    evaluator = None

    try:
        # 设置信号处理器
        def handler(sig, frame):
            return signal_handler(sig, frame, evaluator)

        signal.signal(signal.SIGINT, handler)

        # 创建评估器
        evaluator = BaseEvaluator(task, log_dir, app_path, custom_params=custom_params)

        # 注册回调函数
        evaluator.register_completion_callback(handle_evaluator_event)

        # 启动评估器
        success = evaluator.start()
        if not success:
            print("评估器启动失败")
            return 1

        # 打印操作指南
        print_app_instructions(args.app, args.task, evaluator.instruction)

        # 设置超时
        timeout_seconds = args.timeout
        start_time = time.time()

        # 主循环，等待任务完成或超时，由回调函数设置 evaluation_finished
        while not evaluation_finished:
            # 检查超时
            if time.time() - start_time > timeout_seconds:
                print(f"\n评估超时 ({timeout_seconds}秒)...")
                evaluator.stop()
                time.sleep(10)

        # 如果评估器仍在运行，则停止它
        if evaluator.is_running:
            print("正在停止评估器...")
            evaluator.stop()
            time.sleep(1)  # 给评估器一些时间来结束

        # 获取并打印最终计算出的指标（可选，因为结果已保存到文件）
        final_results = evaluator.result_collector.get_results(evaluator.task_id)
        computed_metrics = final_results.get('computed_metrics', {})
        final_status = computed_metrics.get('task_completion_status', {})

        print("\n评估任务结束！")
        print("最终计算指标:")
        if computed_metrics:
            for key, value in computed_metrics.items():
                value_str = json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, (dict, list)) else value
                print(f"  {key}: {value_str}")
        else:
            print("  未能计算任何指标。")

        print(f"\n最终任务状态: {final_status.get('status', '未知')}")
        if final_status.get('reason'):
            print(f"原因: {final_status.get('reason')}")

        # 查找并显示结果文件位置
        result_file = evaluator.save_results()
        if result_file:
            print(f"\n结果文件保存在: {result_file}")

        # 停止应用
        evaluator.stop_app()

    except Exception as e:
        import traceback

        print(f"评估过程中发生错误: {e}")
        print(traceback.format_exc())
        if evaluator and evaluator.is_running:
            evaluator.stop()
            evaluator.stop_app()
        return 1

    print("评估脚本正常退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())
