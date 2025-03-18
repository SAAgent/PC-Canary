#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram评估器测试脚本
用于测试evaluator对Telegram搜索操作的监测能力

使用方法：
python telegram_evaluator_test.py --telegram-path /path/to/Telegram
"""

import os
import sys
import time
import argparse
import signal
import threading
from typing import Dict, Any

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(PROJECT_ROOT)

from evaluator.core.base_evaluator import BaseEvaluator


# 信号处理函数
def signal_handler(sig, frame, evaluator=None, running_flag=None):
    """
    处理CTRL+C信号
    
    Args:
        sig: 信号类型
        frame: 栈帧
        evaluator: 评估器实例
        running_flag: 运行标志字典
    """
    print("\n\n用户中断测试...")
    
    if running_flag:
        running_flag['running'] = False
    
    if evaluator and evaluator.is_running:
        print("正在停止评估器...")
        evaluator.stop()
    sys.exit(0)


def check_task_completion(evaluator, running_flag):
    """
    定期检查任务是否完成
    
    Args:
        evaluator: 评估器实例
        running_flag: 运行标志字典
    """
    while running_flag['running']:
        # 检查评估器状态
        if not evaluator.is_running:
            print("\n检测到评估器已停止运行，任务可能已完成！")
            running_flag['running'] = False
            break
        
        # 检查评估器的指标字典是否包含success=True
        if hasattr(evaluator, 'metrics') and evaluator.metrics.get('success') is True:
            print("\n检测到任务成功完成！")
            running_flag['running'] = False
            break
            
        # 检查是否存在结果文件
        if hasattr(evaluator, 'result_file') and evaluator.result_file and os.path.exists(evaluator.result_file):
            print(f"\n检测到结果文件已生成: {evaluator.result_file}")
            running_flag['running'] = False
            break
        
        time.sleep(0.5)  # 每0.5秒检查一次


def print_instructions():
    """打印操作指南"""
    print("\n" + "="*60)
    print("Telegram评估器测试运行中...")
    print("请按照以下步骤操作：")
    print("1. 现在可以打开并操作Telegram")
    print("2. 执行搜索操作（根据任务要求）")
    print("3. 评估器会自动监测您的操作")
    print("4. 任务完成后会自动检测并结束")
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
    
    # 运行标志
    running_flag = {'running': True}
    evaluator = None
    
    print(f"初始化Telegram评估器测试...")
    print(f"Telegram路径: {args.telegram_path}")
    print(f"任务路径: {task_path}")
    
    try:
        # 设置信号处理器
        def handler(sig, frame):
            return signal_handler(sig, frame, evaluator, running_flag)
        
        signal.signal(signal.SIGINT, handler)
        
        # 创建评估器
        evaluator = BaseEvaluator(task, log_dir, args.telegram_path)
        evaluator.start()
        
        # 打印操作指南
        print_instructions()
        
        # 启动任务完成检测线程
        completion_thread = threading.Thread(
            target=check_task_completion,
            args=(evaluator, running_flag)
        )
        completion_thread.daemon = True
        completion_thread.start()
        
        # 设置超时
        timeout_seconds = args.timeout
        start_time = time.time()
        
        # 主循环，等待任务完成或超时
        while running_flag['running']:
            # 检查超时
            if time.time() - start_time > timeout_seconds:
                print(f"\n测试超时 ({timeout_seconds}秒)...")
                running_flag['running'] = False
                break
            
            time.sleep(0.5)  # 减少CPU使用
        
        # 主循环结束后，等待评估器完全停止
        if evaluator.is_running:
            print("任务已完成，正在等待评估器停止...")
            evaluator.stop()
            time.sleep(1)  # 给评估器一些时间来结束
            
        # 打印最终结果
        print("\n测试成功完成！")
        if hasattr(evaluator, 'get_results') and callable(getattr(evaluator, 'get_results')):
            results = evaluator.get_results()
            print("评估结果:")
            print(results)
        elif hasattr(evaluator, 'metrics'):
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
        
    except Exception as e:
        print(f"测试过程中发生错误: {e}")
        if evaluator and evaluator.is_running:
            evaluator.stop()
        return 1
    
    print("测试脚本正常退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())