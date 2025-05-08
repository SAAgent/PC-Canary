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
    print("\n\n用户中断测试...")
    
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
    """
    print(f"\n收到评估器事件: {event_data.event_type} - {event_data.message}")
    
    # Use the global flag to signal termination
    global evaluation_finished

    if event_data.event_type == "task_completed": # Check string event type from CallbackEventData
        print(f"任务成功完成")
        # Data associated with the callback itself is in event_data.data (if any)
        # Metrics are now in the result collector, not passed directly here.
        # if hasattr(event_data, 'data') and event_data.data:
        #     print(f"评估指标: {event_data.data.get('metrics', {})}") # Old logic removed
        evaluation_finished = True # Signal the main loop to stop
        # evaluator.stop() # Stop is called after the loop
        # print("任务完成，正在停止评估器...")
        
    elif event_data.event_type == "task_error":
        print(f"任务出错: {event_data.message}")
        evaluation_finished = True # Signal the main loop to stop
    
    elif event_data.event_type == "evaluator_stopped": # If this callback is triggered from stop()
        print(f"评估器已停止: {event_data.message}")
        # evaluation_finished = True # Decide if external stop should also terminate the loop


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
    # task = {
    #     "category": "FreeTube",
    #     "id": "task01_search",
    # }
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
        evaluator = BaseEvaluator(task, log_dir, args.telegram_path,custom_params={"task_parameters":{"query":"sports"}})
        
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
        
        # 主循环，等待任务完成或超时，由回调函数设置 evaluation_finished
        while not evaluation_finished:
            # 检查超时
            if time.time() - start_time > timeout_seconds:
                print(f"\n测试超时 ({timeout_seconds}秒)...")
                break # Exit loop on timeout
            
            time.sleep(0.5)  # 减少CPU使用
        
        # 如果评估器仍在运行（例如，超时退出循环），则停止它
        if evaluator.is_running:
            print("正在停止评估器...")
            evaluator.stop() # Calls end_session, records TASK_END(stopped) if needed, saves results
            time.sleep(1) # Allow time for cleanup
        
        # 打印最终结果
        print("\n测试结束！")

        # 获取并打印最终计算出的指标
        try:
            final_results = evaluator.result_collector.get_results(evaluator.task_id)
            computed_metrics = final_results.get('computed_metrics', {})
            final_status = computed_metrics.get('task_completion_status', {})

            print("最终计算指标:")
            if computed_metrics:
                # Import json if not already imported
                import json
                for key, value in computed_metrics.items():
                    value_str = json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, (dict, list)) else value
                    print(f"  {key}: {value_str}")
            else:
                print("  未能计算任何指标。")

            print(f"\n最终任务状态: {final_status.get('status', '未知')}")
            if final_status.get('reason'):
                print(f"原因: {final_status.get('reason')}")
        except Exception as report_e:
            print(f"获取或打印最终指标时出错: {report_e}")
            
        # 查找并显示结果文件位置 (ResultCollector.save_results now returns path)
        result_file = final_results.get('metadata', {}).get('result_file_path') # Assuming save_results updates metadata
        # If not in metadata, try the old way (less reliable)
        if not result_file:
            result_file_path_from_stop = evaluator.save_results() # Call save_results again if path not stored
            if result_file_path_from_stop:
                 result_file = result_file_path_from_stop
        else:
                # Fallback to searching log dir
            log_files = []
            for root, _, files in os.walk(log_dir):
                for file in files:
                    if file.endswith(".json") and evaluator.task_id in file:
                        log_files.append(os.path.join(root, file))
            if log_files:
                result_file = max(log_files, key=os.path.getmtime)
                
        if result_file:
            print(f"\n结果文件保存在: {result_file}")
        else:
            print("\n未能确定结果文件位置。")

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