#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram评估器测试脚本
用于测试evaluator对Telegram搜索操作的监测能力

使用方法：
python test_evaluator.py --telegram-path /path/to/Telegram
"""

import os
import sys
import time
import argparse
import signal
from typing import Dict, Any

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(PROJECT_ROOT)

from evaluator.core.base_evaluator import BaseEvaluator, EventData, EventType


# 信号处理函数
def signal_handler(sig, frame, evaluator=None):
    """
    处理CTRL+C信号
    
    Args:
        sig: 信号类型
        frame: 栈帧
        evaluator: 评估器实例
    """
    print("\n\n用户中断测试...")
    
    if evaluator and evaluator.is_running:
        print("正在停止评估器...")
        evaluator.stop()
        evaluator.stop_app()
    sys.exit(0)


def handle_evaluator_event(event_data: EventData, evaluator: BaseEvaluator):
    """
    处理评估器事件的回调函数
    
    Args:
        event_data: 事件数据
    """
    print(f"\n收到评估器事件: {event_data.event_type} - {event_data.message}")
    
    if event_data.event_type == EventType.TASK_COMPLETED:
        print(f"任务成功完成: {event_data.message}")
        if hasattr(event_data, 'data') and event_data.data:
            print(f"评估指标: {event_data.data.get('metrics', {})}")
        evaluator.stop()
        print("任务完成，正在停止评估器...")
        
    elif event_data.event_type == EventType.TASK_ERROR:
        print(f"任务出错: {event_data.message}")
    
    elif event_data.event_type == EventType.EVALUATOR_STOPPED:
        print(f"评估器已停止: {event_data.message}")


def print_instructions():
    """打印操作指南"""
    print("\n" + "="*60)
    print("Telegram评估器测试运行中...")
    print("请按照以下步骤操作：")
    print("1. 现在可以打开并操作Telegram")
    print("2. 执行搜索操作（根据任务要求）")
    print("3. 评估器会自动监测您的操作")
    print("4. 任务完成后会自动通过回调函数通知")
    print("5. 随时可按CTRL+C终止测试")
    print("="*60 + "\n")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="评估器测试")
    parser.add_argument("--telegram-path", type=str, required=True,
                       help="Telegram可执行文件路径")
    parser.add_argument("--log-dir", type=str, default="logs",
                       help="日志目录 (默认: logs)")
    parser.add_argument("--timeout", type=int, default=300,
                       help="超时时间，秒 (默认: 300)")
    
    args = parser.parse_args()
    
    # 检查Telegram路径
    if not os.path.exists(args.telegram_path):
        print(f"错误: Telegram可执行文件不存在: {args.telegram_path}")
        return 1
    
    # 任务信息
    task = {
        "category": "telegram",
        "id": "task01_search",
    }
    task_path = os.path.join(PROJECT_ROOT, "tests/tasks/telegram/task01_search")
    
    # 创建日志目录
    log_dir = args.log_dir
    os.makedirs(log_dir, exist_ok=True)
    
    evaluator = None
    
    print(f"初始化Telegram评估器测试...")
    print(f"Telegram路径: {args.telegram_path}")
    print(f"任务路径: {task_path}")
    
    try:
        # 设置信号处理器
        def handler(sig, frame):
            return signal_handler(sig, frame, evaluator)
        
        signal.signal(signal.SIGINT, handler)
        
        # 创建评估器
        evaluator = BaseEvaluator(task, log_dir, args.telegram_path)
        
        # 注册回调函数
        evaluator.register_completion_callback(handle_evaluator_event)
        
        # 启动评估器
        success = evaluator.start()
        if not success:
            print("评估器启动失败")
            return 1
        
        # 打印操作指南
        print_instructions()
        
        # 设置超时
        timeout_seconds = args.timeout
        start_time = time.time()
        
        # 主循环，等待任务完成或超时
        while not evaluator.task_completed:
            # 检查超时
            if time.time() - start_time > timeout_seconds:
                print(f"\n测试超时 ({timeout_seconds}秒)...")
                break
            
            time.sleep(0.5)  # 减少CPU使用
        
        # 如果评估器仍在运行，则停止它
        if evaluator.is_running:
            print("正在停止评估器...")
            evaluator.stop()
            time.sleep(1)  # 给评估器一些时间来结束
        
        # 打印最终结果
        print("\n测试成功完成！")
        if hasattr(evaluator, 'metrics'):
            print("评估指标:")
            print(evaluator.metrics)
            
        # 查找并显示结果文件位置
        result_file = None
        if hasattr(evaluator, 'result_file') and evaluator.result_file:
            result_file = evaluator.result_file
        else:
            # 尝试在日志目录中查找最新的结果文件
            log_files = []
            for root, _, files in os.walk(log_dir):
                for file in files:
                    if file.endswith(".json") and task["id"] in file:
                        log_files.append(os.path.join(root, file))
            
            if log_files:
                result_file = max(log_files, key=os.path.getmtime)
                
        if result_file:
            print(f"结果文件保存在: {result_file}")
        evaluator.stop_app()
        
    except Exception as e:
        import traceback
        print(f"测试过程中发生错误: {e}")
        print(traceback.format_exc())
        if evaluator and evaluator.is_running:
            evaluator.stop()
            evaluator.stop_app()
        return 1
    
    print("测试脚本正常退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())