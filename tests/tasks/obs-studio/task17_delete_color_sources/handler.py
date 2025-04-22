#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, Callable, Set

# 全局评估器实例，由message_handler使用
_EVALUATOR = None
_CONFIG = None
_START_TIME = None
_DELETED_SOURCES = set()  # 用于跟踪已删除的源

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG, _DELETED_SOURCES
    _EVALUATOR = evaluator
    _DELETED_SOURCES.clear()
    
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
                "source_names": ["color1", "color2", "color3"]
            }}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: frida消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _EVALUATOR, _CONFIG, _START_TIME, _DELETED_SOURCES
    
    # 初始化开始时间
    if _START_TIME is None:
        _START_TIME = time.time()
    
    # 检查评估器是否已设置
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None

    # 从frida消息中获取实际的payload
    if message.get("type") != "send":
        return None
    
    payload = message.get("payload", {})

    # 获取事件类型
    event_type = payload.get("type")
    if not event_type:
        return None

    # 处理源删除事件
    if event_type == "source_deleted":
        source_name = payload.get("source_name")
        if source_name in _CONFIG["task_parameters"]["source_names"]:
            _DELETED_SOURCES.add(source_name)
            _EVALUATOR.logger.info(f"源 {source_name} 已删除")
            
            # 检查是否所有需要的源都已删除
            if _DELETED_SOURCES == set(_CONFIG["task_parameters"]["source_names"]):
                _EVALUATOR.update_metric("sources_deleted", True)
                completion_time = time.time() - _START_TIME
                _EVALUATOR.update_metric("time_to_complete", completion_time)
                _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
                return "success"

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