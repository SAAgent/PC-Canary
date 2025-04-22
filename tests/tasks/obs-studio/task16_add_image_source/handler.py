#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器
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
                "source_name": "测试图片",
                "image_path": "test.png",
                "opacity": 50
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

    if message.get("type") == "send" and "payload" in message:
        message = message.get("payload")
    else:
        print("警告: 消息不是send类型或payload不存在")
        return None

    # 获取事件类型
    event_type = message.get("type")
    if not event_type:
        return None

    # 处理图像源添加事件
    if event_type == "image_source_added":
        source_name = message.get("source_name")
        image_path = message.get("image_path")
        
        if (source_name == _CONFIG["task_parameters"]["source_name"] and 
            image_path == _CONFIG["task_parameters"]["image_path"]):
            _EVALUATOR.update_metric("image_source_added", True)
            _EVALUATOR.logger.info("图像源添加成功")

    # 处理不透明度设置事件
    elif event_type == "opacity_set":
        source_name = message.get("source_name")
        opacity = message.get("opacity")
        
        if (source_name == _CONFIG["task_parameters"]["source_name"] and 
            abs(opacity - _CONFIG["task_parameters"]["opacity"]) < 0.1):
            _EVALUATOR.update_metric("opacity_set", True)
            _EVALUATOR.logger.info("不透明度设置成功")

    # 检查是否所有条件都满足
    if (_EVALUATOR.get_metric("image_source_added") and 
        _EVALUATOR.get_metric("opacity_set")):
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