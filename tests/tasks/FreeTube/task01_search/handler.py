#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram搜索任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, Callable

# 全局评估器实例，由message_handler使用
_EVALUATOR = None
_CONFIG = None
_START_TIME = None

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator
    
    # 加载配置
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(current_dir, "config.json")
        
        with open(config_file, 'r') as f:
            _CONFIG = json.load(f)
    except Exception as e:
        if _EVALUATOR:
            _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")
        _CONFIG = {"expected_query": "news"}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: Frida消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _EVALUATOR, _CONFIG, _START_TIME
    
    # 初始化开始时间
    if _START_TIME is None:
        _START_TIME = time.time()
    
    # 检查评估器是否已设置
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None
    
    event_type = message.get('event_type')
    if event_type == 'success':
        _EVALUATOR.logger.info(message.get('message'))
        _EVALUATOR.update_metric("success", True)
        return "success"
    elif event_type == 'keyDown_or_hit_option':
        _EVALUATOR.logger.info(message.get('message'))
    elif event_type == 'hook_keyDown_and_hit_option':
        _EVALUATOR.logger.info(message.get('message'))
        _EVALUATOR.update_metric("hook_keyDown_and_hit_option", True)
    elif event_type == 'click_search_button':
        _EVALUATOR.logger.info(message.get('message'))
    elif event_type == 'hook_search_button':
        _EVALUATOR.logger.info(message.get('message'))
        _EVALUATOR.update_metric("hook_search_button", True)
    elif event_type == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('message')}")
    
    return None


# 提供一个便捷函数来注册事件处理器
def register_handlers(evaluator):
    """
    注册所有事件处理函数到评估器
    
    Args:
        evaluator: 评估器实例
        
    Returns:
        TelegramSearchEventHandler: 事件处理器实例
    """
    # 设置全局评估器，用于message_handler
    set_evaluator(evaluator)
    
    # 回传message_handler函数
    handler = message_handler
    
    # 如果需要，可以启用单独的事件处理器注册（可选）
    # 获取配置文件中定义的事件列表
    # events = handler.config.get("events", {})
    # 
    # # 为每个事件注册处理函数
    # for event_type in events.keys():
    #     # 创建闭包来保留event_type值
    #     def create_handler(event_type):
    #         return lambda payload: handler.handle_event(event_type, payload)
    #     
    #     evaluator.register_event_handler(event_type, create_handler(event_type))
    
    return handler
