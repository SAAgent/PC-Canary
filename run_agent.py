#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram搜索任务测试程序 - 使用代码执行环境控制器
"""

import os
import sys
import time
import argparse
from PIL import ImageGrab

# 导入Agent相关模块
from agent.base_agent import BaseAgent
from agent.models.openai_model import OpenAIModel
from agent.models.gemini_model import GeminiModel

# 导入控制器
from env.controller.code_execution_controller import CodeExecutionController



def create_model(model_type, api_key):
    """
    创建模型实例
    
    Args:
        model_type: 模型类型 ('openai' 或 'gemini')
        api_key: API密钥
        
    Returns:
        模型实例
    """
    if model_type.lower() == 'openai':
        return OpenAIModel(
            api_key=api_key,
            model_name="qwen-omni-turbo",
            temperature=0.2,
            max_tokens=2048
        )
    elif model_type.lower() == 'gemini':
        return GeminiModel(
            api_key=api_key,
            model_name="gemini-1.5-pro",
            temperature=0.2,
            max_output_tokens=2048
        )
    elif model_type.lower() == 'qwen':
        return OpenAIModel(
            api_key=api_key,
            model_name="qwen-vl-max",
            api_base="https://dashscope.aliyuncs.com/compatible-mode/v1",
            temperature=0.2,
            max_tokens=2048
        )
    else:
        raise ValueError(f"不支持的模型类型: {model_type}")


def test_agent_telegram_search(model_type='openai', api_key=None, max_steps=10):
    """
    测试Agent执行任务
    
    Args:
        model_type: 模型类型 ('openai' 或 'gemini')
        api_key: API密钥 (如果为None，则尝试从环境变量获取)
        max_steps: 最大执行步骤数
        
    Returns:
        bool: 任务是否成功完成
    """
    # 检查API密钥
    if api_key is None:
        if model_type.lower() == 'openai':
            api_key = os.environ.get('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("未提供OpenAI API密钥，请设置OPENAI_API_KEY环境变量或直接传入api_key参数")
        elif model_type.lower() == 'gemini':
            api_key = os.environ.get('GOOGLE_API_KEY')
            if not api_key:
                raise ValueError("未提供Google API密钥，请设置GOOGLE_API_KEY环境变量或直接传入api_key参数")
        elif model_type.lower() == 'qwen':
            api_key = os.environ.get('DASHSCOPE_API_KEY')
            if not api_key:
                raise ValueError("未提供Dashscope API密钥，请设置DASHSCOPE_API_KEY环境变量或直接传入api_key参数")
    
    # 创建模型
    model = create_model(model_type, api_key)
    
    # 创建代码执行环境控制器
    controller = CodeExecutionController()
    
    # 创建Agent
    agent = BaseAgent(model, observation_type="screenshot", action_space="pyautogui-muti-action")
    
    # 定义Telegram搜索任务指令
    instructions = """
    任务：在Telegram应用中执行搜索操作
    
    步骤：
    1. 启动Telegram应用程序（如果已打开，请确保它在前台）
    2. 点击搜索按钮（通常位于应用程序顶部）
    3. 在搜索框中输入"news"
    4. 等待搜索结果显示
    
    注意事项：
    - 你可以使用pyautogui库来控制鼠标和键盘
    - 你可以使用WAIT命令来等待界面响应（例如：WAIT）
    - 当任务完成时，请使用DONE命令
    - 如果任务无法完成，请使用FAIL命令
    - 你可以访问的环境变量和库：pyautogui, time, os, sys, re, json, PIL, ImageGrab
    - 你可以通过controller变量访问控制器实例
    """
    
    # 创建截图保存目录
    logs_dir = "tests/logs"
    os.makedirs(logs_dir, exist_ok=True)
    
    # 执行步骤
    step_index = 0
    start_time = time.time()
    
    # 屏幕截图历史记录
    screenshot_history = []
    
    print(f"\n开始执行Telegram搜索任务，使用{model_type}模型\n")
    print(f"任务指令:\n{instructions}\n")
    
    # 执行Agent循环
    while step_index < max_steps and not controller.task_completed and not controller.task_failed:
        print(f"\n执行步骤 {step_index+1}/{max_steps}")
        
        # 获取观察
        print("获取屏幕截图...")
        observation = controller.get_screenshot()
        
        # 保存截图，方便调试
        screenshot_path = os.path.join(logs_dir, f"step_{step_index+1}_screenshot_{int(time.time())}.png")
        observation.save(screenshot_path)
        print(f"截图已保存: {screenshot_path}")
        
        # 将截图添加到历史记录
        screenshot_history.append(screenshot_path)
        if len(screenshot_history) > 3:  # 只保留最近3张截图
            screenshot_history.pop(0)
        
        # 执行Agent决策
        print("Agent开始决策...")
        action_code, thought = agent.act(instructions, observation, controller)
        
        # 打印Agent思考和动作
        print(f"\nAgent思考:")
        print("-" * 50)
        print(thought[:500] + ("..." if len(thought) > 500 else ""))
        print("-" * 50)
        
        print(f"\nAgent动作:")
        print("-" * 50)
        print(action_code[:500] + ("..." if len(action_code) > 500 else ""))
        print("-" * 50)
        
        # 检查环境状态
        if controller.task_completed:
            print("任务已完成！")
            break
        elif controller.task_failed:
            print(f"任务失败！原因: {controller.failure_reason}")
            break
            
        # 继续执行下一步
        step_index += 1
        
        # 检查是否超时
        elapsed_time = time.time() - start_time
        if elapsed_time > 300:  # 5分钟超时
            print("测试超时，终止执行")
            break
        
        # 用户可以手动中断
        print("\n按 'q' 退出，或按任意键继续...")
        if sys.stdin.isatty():  # 检查是否在交互式终端
            try:
                import termios, tty, select
                old_settings = termios.tcgetattr(sys.stdin)
                try:
                    tty.setcbreak(sys.stdin.fileno())
                    if select.select([sys.stdin], [], [], 0.5)[0]:
                        key = sys.stdin.read(1)
                        if key == 'q':
                            print("用户手动终止测试")
                            break
                finally:
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except (ImportError, termios.error):
                pass
    
    # 生成简单报告
    print("\n" + "="*50)
    print("Agent测试执行报告")
    print("="*50)
    print(f"总执行步骤: {step_index}")
    print(f"执行状态: {'成功' if controller.task_completed else '失败' if controller.task_failed else '未完成'}")
    if controller.task_failed and controller.failure_reason:
        print(f"失败原因: {controller.failure_reason}")
    print(f"总执行时间: {time.time() - start_time:.2f} 秒")
    
    # 保存报告
    with open(os.path.join(logs_dir, f"telegram_search_agent_report_{int(time.time())}.txt"), "w") as f:
        f.write(f"Agent测试执行报告\n")
        f.write(f"任务: Telegram搜索\n")
        f.write(f"模型: {model_type}\n")
        f.write(f"总执行步骤: {step_index}\n")
        f.write(f"执行状态: {'成功' if controller.task_completed else '失败' if controller.task_failed else '未完成'}\n")
        if controller.task_failed and controller.failure_reason:
            f.write(f"失败原因: {controller.failure_reason}\n")
        f.write(f"总执行时间: {time.time() - start_time:.2f} 秒\n")
        f.write(f"截图历史: {', '.join(screenshot_history)}\n")
    
    return controller.task_completed


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="测试Agent执行Telegram搜索任务")
    parser.add_argument("--model", choices=["openai", "gemini", "qwen"], default="qwen",
                        help="使用的模型类型 (默认: openai)")
    parser.add_argument("--api_key", type=str, help="API密钥 (如果未提供则从环境变量获取)")
    parser.add_argument("--max_steps", type=int, default=10, help="最大执行步骤数 (默认: 10)")
    
    args = parser.parse_args()
    
    try:
        # 测试Agent
        success = test_agent_telegram_search(
            model_type=args.model,
            api_key=args.api_key,
            max_steps=args.max_steps
        )
        
        print(f"\n测试{'成功' if success else '失败'}")
        
    except KeyboardInterrupt:
        print("\n用户中断，退出程序")
    except Exception as e:
        print(f"\n执行出错: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()