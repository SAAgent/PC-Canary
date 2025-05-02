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
from agent.models.claude_model import ClaudeModel

# 导入评估器
from evaluator.core.base_evaluator import BaseEvaluator, CallbackEventData
from evaluator.core.base_evaluator import AgentEvent

# 导入环境控制器
from env.controller.code_execution_controller import CodeExecutionController

start_time = None
# Global flag similar to run_evaluator.py
evaluation_finished = False

def handle_evaluator_event(event_data: CallbackEventData, evaluator: BaseEvaluator = None):
    """处理评估器事件的回调函数"""
    print(f"\n收到评估器事件: {event_data.event_type} - {event_data.message}")

    global evaluation_finished

    if event_data.event_type == "task_completed":
        print(f"评估器报告任务成功完成: {event_data.message}")
        evaluation_finished = True # Signal loop termination

    elif event_data.event_type == "task_error":
        print(f"评估器报告任务出错: {event_data.message}")
        evaluation_finished = True # Signal loop termination

    elif event_data.event_type == "evaluator_stopped":
        print(f"评估器已停止: {event_data.message}")
        # evaluation_finished = True # Optionally stop loop on external stop

def _generate_report(evaluator, agent_success):
    """生成报告"""
    # 生成报告
    print("\n" + "="*60)
    print("Agent系统与评估器执行报告")
    print("="*60)
    print(f"执行时间: {time.time() - start_time:.2f} 秒")
    
    # 获取评估结果
    final_results = evaluator.result_collector.get_results(evaluator.task_id)
    computed_metrics = final_results.get('computed_metrics', {})
    final_status = computed_metrics.get('task_completion_status', {})
    eval_success = final_status.get('status') == 'success'
    
    # 对比结果
    print("\n结果对比:")
    print(f"- Agent系统结果: {'成功' if agent_success else '失败'}")
    print(f"- 评估器结果: {'成功' if eval_success else '失败'} (状态: {final_status.get('status', '未知')})")
    
    # 检查结果一致性
    is_consistent = (agent_success == eval_success)
    print(f"- 结果一致性: {'一致' if is_consistent else '不一致'}")
    
    # 打印评估器详细结果
    print("\n评估指标详情:")
    if computed_metrics:
        import json # Make sure json is imported
        for key, value in computed_metrics.items():
            value_str = json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, (dict, list)) else value
            print(f"- {key}: {value_str}")
    else:
        print("- 未计算任何指标。")
    
    # Fetch result file path from metadata if available
    result_file = final_results.get('metadata', {}).get('result_file_path')
    if result_file:
        print(f"\n结果文件: {result_file}")
    else:
        print("\n结果文件路径未在元数据中找到。") # save_results is called in finally block
    
    print("\n" + "="*60)
    print("执行完成")
    print("="*60 + "\n")
    
    return agent_success, eval_success

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="运行带评估器的Agent系统")
    parser.add_argument("--model", choices=["openai", "gemini", "qwen", "claude"], default="claude",
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
    elif args.model == 'claude':
        if api_key is None:
            api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("使用 Claude 模型需要提供 API Key (通过 --api_key 或 ANTHROPIC_API_KEY 环境变量)")
        model = ClaudeModel(
            api_key=api_key,
            model_name="claude-3-sonnet-20240229",
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
        
        while step_index < args.max_steps and not evaluation_finished:
            print(f"\n执行步骤 {step_index+1}/{args.max_steps}")
            current_time = time.time() # For event timestamps

            # 检查是否超时
            if current_time - start_time > args.timeout:
                print(f"\n执行超时 ({args.timeout}秒)")
                # Don't call evaluator.stop() here, let finally block handle it
                break

            # 获取观察
            print("获取屏幕截图...")
            observation = controller.get_screenshot()
            if not observation:
                print("无法获取屏幕截图，跳过此步骤")
                time.sleep(1) # Avoid rapid looping on error
                continue

            # --- LLM 调用事件 --- #
            print("Agent开始决策...")
            llm_start_time = time.time()
            evaluator.record_event(AgentEvent.LLM_QUERY_START, {
                'timestamp': llm_start_time,
                'model_name': agent.model.model_name # Assuming model has model_name attribute
            })
            action_code = None
            thought = None
            llm_error = None
            llm_success = False
            try:
                # action, args, usage_info = agent.act(instructions, observation, controller)
                # Unpack the three return values
                returned_action, returned_args, usage_info = agent.act(instructions, observation, controller)
                llm_success = True # LLM call itself succeeded if no exception
            except Exception as llm_e:
                llm_error = str(llm_e)
                print(f"Agent决策时发生错误: {llm_error}")
                # usage_info might still be None here if error happened before return

            llm_end_time = time.time()
            # Record LLM_QUERY_END using the returned usage_info
            evaluator.record_event(AgentEvent.LLM_QUERY_END, {
                'timestamp': llm_end_time,
                'status': 'success' if llm_success else 'error',
                'error': llm_error,
                'prompt_tokens': usage_info.get('prompt_tokens') if usage_info else None,
                'completion_tokens': usage_info.get('completion_tokens') if usage_info else None,
                'cost': None # Cost calculation not implemented
            })

            # Check if LLM call failed or returned nothing actionable initially
            if not llm_success:
                print("LLM 调用失败，跳过此步骤。")
                time.sleep(1)
                continue
            if returned_action is None and returned_args and returned_args.get("error"):
                print(f"LLM 返回错误或无法解析: {returned_args.get('error')}")
                time.sleep(1)
                continue

            # --- Handle special instructions returned by Agent --- #
            if returned_action == "finish":
                print("Agent 报告任务完成 (finish)。")
                agent_success = True
                reasoning = returned_args.get('reasoning', 'No reasoning provided') if returned_args else 'No reasoning provided'
                evaluator.record_event(AgentEvent.AGENT_REPORTED_COMPLETION, {
                    'timestamp': time.time(),
                    'reasoning': reasoning
                })
                break # Exit the main loop

            elif returned_action == "wait":
                print("Agent 请求等待，跳过执行。")
                time.sleep(1) # Implement actual wait or just continue
                continue # Skip code execution for this step

            elif returned_action == "fail":
                print("Agent 报告任务失败 (fail)。")
                agent_success = False
                reasoning = returned_args.get('reasoning', 'No reasoning provided') if returned_args else 'No reasoning provided'
                # Optionally record an event here if needed, though handler might record TASK_END
                # evaluator.record_event(...) 
                break # Exit the main loop

            # --- If it's code, proceed with execution --- # 
            action_code = returned_action # Now we know it should be code
            if not isinstance(action_code, str):
                 print(f"错误: agent.act 返回的动作不是预期的代码字符串或特殊指令: {action_code}")
                 time.sleep(1)
                 continue

            # --- Action (Tool) 执行事件 --- #
            print(f"准备执行动作代码: {action_code[:100]}...") # Log snippet
            tool_start_time = time.time()
            tool_name = "code_execution"
            evaluator.record_event(AgentEvent.TOOL_CALL_START, {
                'timestamp': tool_start_time,
                'tool_name': tool_name,
                'args': {'code': action_code} # Store code as args
            })
            execution_result = None
            tool_error = None
            tool_success = False
            try:
                execution_result = agent._execute_action(action_code, controller)
                tool_success = True # Assume success if no exception
                print(f"动作执行结果: {execution_result}")
            except Exception as tool_e:
                tool_error = str(tool_e)
                print(f"动作执行时发生错误: {tool_error}")

            tool_end_time = time.time()
            evaluator.record_event(AgentEvent.TOOL_CALL_END, {
                'timestamp': tool_end_time,
                'tool_name': tool_name,
                'success': tool_success,
                'result': execution_result if tool_success else None,
                'error': tool_error
            })

            # 检查环境状态 (由 Evaluator 触发的回调会设置 evaluation_finished)
            # if controller.task_completed: # Rely on evaluator callback now
            #     print("Agent报告任务已完成！")
            #     agent_success = True
            #     break
            # elif controller.task_failed: # Rely on evaluator callback now
            #     print(f"Agent报告任务失败！原因: {controller.failure_reason}")
            #     break

            # Agent 自身是否认为完成？ (如果 agent.act 返回此信息)
            # agent_thinks_complete = thought.get('final_answer') is not None # Example check
            # if agent_thinks_complete:
            #    evaluator.record_event(AgentEvent.AGENT_REPORTED_COMPLETION, { 'timestamp': time.time(), 'reasoning': thought })

            # 继续执行下一步
            step_index += 1
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