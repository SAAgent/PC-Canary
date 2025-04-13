#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
集成Agent系统与评估器的脚本
"""

import os
import sys
import time
import argparse
import signal
from PIL import Image

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(PROJECT_ROOT)

# 导入Agent相关模块 - 根据实际结构调整
from agent.base_agent import BaseAgent
from agent.models.openai_model import OpenAIModel

# 导入评估器
from evaluator.core.base_evaluator import BaseEvaluator, EventData, EventType

# 导入环境控制器
from env.controller.code_execution_controller import CodeExecutionController


start_time = None
# 全局变量，用于跟踪任务状态
task_state = {
    'completed': False,
    'success': False,
    'message': '',
    'metrics': {}
}
    
def handle_evaluator_event(event_data: EventData, evaluator: BaseEvaluator = None):
    """处理评估器事件的回调函数"""
    print(f"\n收到评估器事件: {event_data.event_type} - {event_data.message}")
    
    if event_data.event_type == EventType.TASK_COMPLETED:
        task_state['completed'] = True
        task_state['success'] = True
        task_state['message'] = event_data.message
        print(f"任务成功完成: {event_data.message}")
        # 更新指标数据
        if hasattr(event_data, 'data') and event_data.data:
            metrics = event_data.data.get('metrics', {})
            task_state['metrics'] = metrics
            print(f"评估指标: {metrics}")
    
    elif event_data.event_type == EventType.TASK_ERROR:
        task_state['completed'] = True
        task_state['success'] = False
        task_state['message'] = event_data.message
        print(f"任务出错: {event_data.message}")
    
    elif event_data.event_type == EventType.EVALUATOR_STOPPED:
        print(f"评估器已停止: {event_data.message}")
    
def _generate_report(evaluator, agent_success):
    """生成报告"""
    # 生成报告
    print("\n" + "="*60)
    print("Agent系统与评估器执行报告")
    print("="*60)
    print(f"执行时间: {time.time() - start_time:.2f} 秒")
    
    # 获取评估结果
    eval_success = task_state['success']
    
    # 对比结果
    print("\n结果对比:")
    print(f"- Agent系统结果: {'成功' if agent_success else '失败'}")
    print(f"- 评估器结果: {'成功' if eval_success else '失败'}")
    
    # 检查结果一致性
    is_consistent = (agent_success == eval_success)
    print(f"- 结果一致性: {'一致' if is_consistent else '不一致'}")
    
    # 打印评估器详细结果
    if task_state['metrics']:
        print("\n评估指标详情:")
        for key, value in task_state['metrics'].items():
            print(f"- {key}: {value}")
    elif hasattr(evaluator, 'metrics'):
        print("\n评估指标详情:")
        for key, value in evaluator.metrics.items():
            print(f"- {key}: {value}")
    
    if hasattr(evaluator, 'result_file') and evaluator.result_file:
        print(f"\n结果文件: {evaluator.result_file}")
    
    print("\n" + "="*60)
    print("执行完成")
    print("="*60 + "\n")
    
    return agent_success, eval_success

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="运行带评估器的Agent系统")
    parser.add_argument("--model", choices=["openai", "gemini", "qwen"], default="openai",
                        help="使用的模型类型 (默认: openai)")
    parser.add_argument("--api_key", type=str, default=None,
                        help="API密钥 (如果未提供则从环境变量获取)")
    parser.add_argument("--app_path", type=str, default="apps/tdesktop/out/Debug/Telegram",
                        help="Telegram应用路径 (默认: apps/tdesktop/out/Debug/Telegram)")
    parser.add_argument("--max_steps", type=int, default=10, 
                        help="最大执行步骤数 (默认: 10)")
    parser.add_argument("--log_dir", type=str, default="logs",
                        help="日志目录 (默认: logs)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="超时时间，秒 (默认: 300)")
    
    args = parser.parse_args()
    
    # 检查API密钥
    api_key = args.api_key
    if args.model == 'openai':
        if api_key is None:
            api_key = os.environ.get('OPENAI_API_KEY')
        model = OpenAIModel(
            api_key=api_key,
            model_name="gpt-4o-mini",
            temperature=0.2,
            max_tokens=2048
        )
    elif args.model == 'qwen':
        if api_key is None:
            api_key = os.environ.get('DASHSCOPE_API_KEY')
        model = OpenAIModel(
            api_key=api_key,
            model_name="qwen-vl-max",
            api_base="https://dashscope.aliyuncs.com/compatible-mode/v1",
            temperature=0.2,
            max_tokens=2048
        )
    else:
        raise ValueError(f"不支持的模型类型: {args.model}")

        
    # 检查应用路径
    if not os.path.exists(args.app_path):
        print(f"警告: Telegram应用路径不存在: {args.app_path}")
        if input("是否继续执行? (y/n): ").lower() != 'y':
            return 1
    
    # 创建控制器
    controller = CodeExecutionController()
    # 创建Agent
    agent = BaseAgent(model, observation_type="screenshot", action_space="pyautogui-muti-action")
    # 创建评估器
    task = {
        "category": "telegram",
        "id": "task01_search",
    }
    evaluator = BaseEvaluator(task, args.log_dir, args.app_path)
    
    # 设置信号处理
    def _signal_handler(sig, frame):
        """信号处理函数"""
        print("\n\n用户中断执行...")
        if evaluator and evaluator.is_running:
            print("正在停止评估器...")
            evaluator.stop()
            evaluator.stop_app()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, _signal_handler)
    os.makedirs(args.log_dir, exist_ok=True)

    print("\n" + "="*60)
    print(f"运行带评估器的Agent系统 - 使用{args.model}模型")
    print("="*60)
    print(f"任务: 在Telegram中搜索'news'")
    print(f"最大步骤数: {args.max_steps}")
    print(f"应用路径: {args.app_path}")
    print("="*60 + "\n")

    # 注册回调函数
    evaluator.register_completion_callback(handle_evaluator_event)
    
    print("[*] 启动评估器...")
    success = evaluator.start()
    if not success:
        print("评估器启动失败")
        return 1
    
    global start_time
    # 记录开始时间
    start_time = time.time()
    
    # 定义Telegram搜索任务指令
    instructions = """
    任务：在Telegram应用中执行搜索操作
    
    步骤：
    1. 启动Telegram应用程序（如果已打开，请确保它在前台）
    2. 点击搜索按钮（通常位于应用程序顶部）
    3. 在搜索框中输入"news"
    4. 等待搜索结果显示
    """
    
    # 运行Agent系统
    agent_success = False
    try:
        print("\n[*] 开始执行Agent系统...")
        
        # 执行步骤
        step_index = 0
        
        while step_index < args.max_steps and not task_state['completed']:
            print(f"\n执行步骤 {step_index+1}/{args.max_steps}")
            
            # 检查是否超时
            if time.time() - start_time > args.timeout:
                print(f"\n执行超时 ({args.timeout}秒)")
                break
            
            # 获取观察
            print("获取屏幕截图...")
            observation = controller.get_screenshot()
            
            # 执行Agent决策
            print("Agent开始决策...")
            action_code, thought = agent.act(instructions, observation, controller)
            
            # 执行代码并获取执行结果
            execution_result = agent._execute_action(action_code, controller)
            
            # 检查环境状态
            if controller.task_completed:
                print("Agent报告任务已完成！")
                agent_success = True
                break
            elif controller.task_failed:
                print(f"Agent报告任务失败！原因: {controller.failure_reason}")
                break
                
            # 继续执行下一步
            step_index += 1
            
            # 检查评估器是否已标记成功
            if task_state['completed']:
                print("\n评估器报告任务已完成")
                if task_state['success']:
                    agent_success = True
                break
            
            # 短暂等待以允许回调处理
            time.sleep(0.5)
        
        # 打印Agent执行结果
        print(f"\n[*] Agent执行{'成功' if agent_success else '失败'}")
        
        # 等待评估器完成处理
        print("[*] 等待评估器完成处理...")
        time.sleep(3)
        
    except KeyboardInterrupt:
        print("\n[!] 用户中断执行")
    except Exception as e:
        print(f"\n[!] 执行错误: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # 停止评估器
        if evaluator.is_running:
            print("\n[*] 停止评估器...")
            evaluator.stop()
        
        # 停止应用
        if hasattr(evaluator, 'stop_app'):
            evaluator.stop_app()
    
    agent_success, eval_success = _generate_report(evaluator, agent_success)
    overall_success = agent_success and eval_success
    print(f"\n总体执行结果: {'成功' if overall_success else '失败'}")
    return 0 if overall_success else 1


if __name__ == "__main__":
    sys.exit(main()) 