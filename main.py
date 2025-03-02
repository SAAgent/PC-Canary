#!/usr/bin/env python3
"""
简化版 PC 环境控制 Agent 主程序

这个程序使用 GPT-4o 模型实现一个简单的 Agent，
接收一个指令，分析当前屏幕，并执行相应操作。
支持从 YAML 配置文件加载参数。
"""

import os
import sys
import time
import argparse
import logging
import yaml
from pathlib import Path
from PIL import ImageGrab
from datetime import datetime

from agent.base_agent import BaseAgent
from agent.models.openai_model import OpenAIModel
from env.controller.pyautogui_control import PyautoguiController


# 默认配置文件路径
DEFAULT_CONFIG_PATH = "config.yaml"

# 设置日志格式
def setup_logging(level_name="info", log_file=None):
    """设置日志配置"""
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR
    }
    level = level_map.get(level_name.lower(), logging.INFO)
    
    # 配置根日志记录器
    logger = logging.getLogger()
    logger.setLevel(level)
    
    # 清除现有处理程序
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 添加控制台处理程序
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 如果指定了日志文件，添加文件处理程序
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def load_config(config_path=DEFAULT_CONFIG_PATH):
    """
    从 YAML 文件加载配置
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        包含配置的字典
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.warning(f"配置文件 '{config_path}' 未找到，将使用默认值")
        return {}
    except yaml.YAMLError as e:
        logging.error(f"解析配置文件时出错: {e}")
        return {}


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='简化版 PC 环境控制 Agent')
    parser.add_argument('--config', type=str, default=DEFAULT_CONFIG_PATH,
                       help=f'配置文件路径 (默认: {DEFAULT_CONFIG_PATH})')
    parser.add_argument('--api_key', type=str, 
                        help='OpenAI API 密钥 (覆盖配置文件)')
    parser.add_argument('--instruction', type=str, required=True, 
                        help='要执行的指令，例如："打开浏览器并搜索天气"')
    parser.add_argument('--steps', type=int,
                        help='最大执行步骤数 (默认: 配置文件或 5)')
    parser.add_argument('--delay', type=float,
                        help='每步之间的延迟时间(秒) (默认: 配置文件或 1.0)')
    parser.add_argument('--save_screenshots', action='store_true',
                       help='保存执行过程中的截图 (默认: 配置文件或 False)')
    return parser.parse_args()


def get_screenshot(save_screenshots=False, screenshots_dir="screenshots"):
    """
    获取当前屏幕截图
    
    Args:
        save_screenshots: 是否保存截图
        screenshots_dir: 截图保存目录
        
    Returns:
        PIL.Image: 屏幕截图
    """
    screenshot = ImageGrab.grab()
    
    # 如果需要保存截图
    if save_screenshots:
        # 确保截图目录存在
        Path(screenshots_dir).mkdir(parents=True, exist_ok=True)
        
        # 生成时间戳文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{screenshots_dir}/screenshot_{timestamp}.png"
        
        # 保存截图
        screenshot.save(filename)
        logging.debug(f"截图已保存至 {filename}")
    
    return screenshot


def main():
    """主函数"""
    # 解析命令行参数
    args = parse_args()
    
    # 加载配置文件
    config = load_config(args.config)
    
    # 设置日志记录
    log_config = config.get('logging', {})
    logger = setup_logging(
        level_name=log_config.get('level', 'info'),
        log_file=log_config.get('file')
    )
    
    # 合并配置参数和命令行参数
    execution_config = config.get('execution', {})
    max_steps = args.steps or execution_config.get('max_steps', 5)
    delay = args.delay or execution_config.get('delay', 1.0)
    save_screenshots = args.save_screenshots or execution_config.get('save_screenshots', False)
    screenshots_dir = execution_config.get('screenshots_dir', 'screenshots')
    
    # 获取 API 密钥
    api_key = args.api_key or config.get('api_keys', {}).get('openai') or os.environ.get('OPENAI_API_KEY', '')
    
    # 检查 API 密钥
    if not api_key:
        logging.error("错误: 未提供 OpenAI API 密钥。请通过命令行参数、配置文件或环境变量提供。")
        sys.exit(1)
    
    # 初始化控制器
    controller = PyautoguiController()
    logging.info("控制器初始化成功")
    
    # 获取模型配置
    openai_config = config.get('models', {}).get('openai', {})
    model_name = openai_config.get('model_name', 'gpt-4o')
    temperature = openai_config.get('temperature', 0.2)
    top_p = openai_config.get('top_p', 0.95)
    max_tokens = openai_config.get('max_tokens', 2048)
    
    # 初始化 GPT-4o 模型
    try:
        model = OpenAIModel(
            api_key=api_key,
            model_name=model_name,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens
        )
        logging.info(f"使用 OpenAI 模型 ({model_name}) 初始化成功")
    except Exception as e:
        logging.error(f"初始化模型失败: {e}")
        sys.exit(1)
    
    # 创建 Agent
    agent = BaseAgent(
        model=model,
        observation_type="screenshot",
        action_space="pyautogui-muti-action"
    )
    logging.info("Agent 初始化成功")
    
    # 打印开始信息
    print(f"\n{'='*50}")
    print(f"开始执行指令: {args.instruction}")
    print(f"使用模型: {model_name}")
    print(f"最大步骤数: {max_steps}")
    print(f"每步延迟: {delay}秒")
    print(f"保存截图: {'是' if save_screenshots else '否'}")
    print(f"{'='*50}\n")
    
    # 主循环
    step = 0
    action = None
    while step < max_steps:
        step += 1
        logging.info(f"执行步骤 {step}/{max_steps}")
        print(f"\n===== 步骤 {step}/{max_steps} =====")
        
        # 获取屏幕截图
        print("获取屏幕截图...")
        screenshot = get_screenshot(save_screenshots, screenshots_dir)
        
        # Agent 执行决策和动作
        try:
            print("分析屏幕并决定下一步行动...")
            action, thought = agent.act(
                instruction=args.instruction,
                observation=screenshot,
                controller=controller
            )
            
            # 打印执行情况
            print(f"\n思考过程:\n{thought}")
            print(f"\n执行动作:\n{action}")
            logging.info(f"执行动作: {action[:100]}..." if len(action) > 100 else f"执行动作: {action}")
            
            # 检查是否完成任务
            if action == "DONE":
                print("\n✓ 任务完成!")
                logging.info("任务完成")
                break
            elif action == "FAIL":
                print("\n✗ 任务失败，无法继续执行。")
                logging.warning("任务失败")
                break
            elif action == "WAIT":
                print("\n⌛ 等待中...")
                logging.info("等待中")
            
            # 添加延迟
            print(f"等待 {delay} 秒...")
            time.sleep(delay)
            
        except KeyboardInterrupt:
            print("\n\n用户中断，程序停止")
            logging.info("用户中断程序")
            break
        except Exception as e:
            print(f"\n执行过程中出错: {e}")
            logging.error(f"执行出错: {e}", exc_info=True)
            break
    
    if step >= max_steps and action not in ["DONE", "FAIL"]:
        print(f"\n达到最大步骤数 {max_steps}，执行结束。")
        logging.info(f"达到最大步骤数 {max_steps}")
    
    print("\n程序结束")
    logging.info("程序结束")


if __name__ == "__main__":
    main()
