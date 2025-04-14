#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeTube搜索任务事件处理器
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
    
    # 使用评估器的已更新配置，而不是重新读取文件
    if hasattr(evaluator, 'config') and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("使用评估器中的更新配置")
    else:
        # 作为备份，如果评估器中没有配置，才从文件读取
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "config.json")
            
            with open(config_file, 'r') as f:
                _CONFIG = json.load(f)
                _EVALUATOR.logger.info("从文件加载配置")
        except Exception as e:
            if _EVALUATOR:
                _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")
            # 提供一个默认配置以避免空引用
            _CONFIG = {"task_parameters": {"query": "porsche"}}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: injector消息对象
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
    if event_type == 'search_by_enter' or event_type == 'click_search_button':
        input_data = message.get('inputData')
        _EVALUATOR.logger.info(message.get('message') + ": " + input_data)
        expected_query = _CONFIG.get("task_parameters", {}).get("query", "porsche")
        if input_data == expected_query:
            _EVALUATOR.update_metric("success", True)
            # update time
            completion_time = time.time() - _START_TIME
            _EVALUATOR.update_metric("time_to_complete", completion_time)
            _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
            return "success"
    elif event_type == 'hook_keyDown_and_hit_option':
        _EVALUATOR.logger.info(message.get('message'))
        _EVALUATOR.update_metric("hook_keyDown_and_hit_option", True)
    elif event_type == 'hook_search_button':
        _EVALUATOR.logger.info(message.get('message'))
        _EVALUATOR.update_metric("hook_search_button", True)
    elif event_type == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('message')}")
    
    return None

def register_handlers(evaluator):
    """
    注册所有事件处理函数到评估器
    
    Args:
        evaluator: 评估器实例
        
    Returns:
        message_handler: 处理函数
    """
    # 设置全局评估器，用于message_handler
    set_evaluator(evaluator)
    return message_handler
