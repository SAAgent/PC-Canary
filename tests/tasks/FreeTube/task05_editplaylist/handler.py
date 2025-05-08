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
            _CONFIG = {"task_parameters": {
                "origin_name": "Watch Later",
                "expected_name": "Course",
                "expected_description": "MIT"
            }}

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
    _EVALUATOR.logger.info(message.get('message'))
    if event_type == "find_name_inputbox":
        _EVALUATOR.update_metric("name", message.get("data"))
        if "origin_name" not in _EVALUATOR.metrics:
            _EVALUATOR.update_metric("origin_name", message.get("data"))
        _EVALUATOR.update_metric(event_type, True)
    elif event_type == "find_description_inputbox":
        _EVALUATOR.update_metric("description", message.get("data"))
        _EVALUATOR.update_metric(event_type, True)
    elif event_type == "hook_name_inputbox_click"\
        or event_type == "hook_name_inputbox_input"\
        or event_type == "hook_description_inputbox_click"\
        or event_type == "hook_description_inputbox_input":
        _EVALUATOR.update_metric(event_type, True)
    elif event_type == "edit_name":
        _EVALUATOR.update_metric("name", message.get("data"))
    elif event_type == "edit_description":
        _EVALUATOR.update_metric("description", message.get("data"))
    elif event_type == "save_edit_by_enter" or event_type == "save_by_click_button":
        expected_origin_name = _CONFIG.get("task_parameters", {}).get("origin_name", "Watch Later")
        expected_name = _CONFIG.get("task_parameters", {}).get("expected_name", "Course")
        expected_description = _CONFIG.get("task_parameters", {}).get("expected_description", "MIT")
        name = _EVALUATOR.metrics["name"]
        description = _EVALUATOR.metrics["description"]
        origin_name = _EVALUATOR.metrics["origin_name"]
        if origin_name == expected_origin_name\
            and name == expected_name\
            and description == expected_description:
            _EVALUATOR.update_metric("success", True)
            # update time
            completion_time = time.time() - _START_TIME
            _EVALUATOR.update_metric("time_to_complete", completion_time)
            _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
            return "success"
        else:
            _EVALUATOR.logger.info(f"触发保存, 但不成功: {name}, {description}, {origin_name}")
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
