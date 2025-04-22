#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional

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
            raise

def check_transition_config(transition_name: str, duration_ms: int) -> bool:
    """检查转场配置是否符合要求"""
    expected_name = _CONFIG["task_parameters"]["transition_name"]
    expected_duration = _CONFIG["task_parameters"]["duration_ms"]
    
    name_match = transition_name == expected_name
    duration_match = duration_ms == expected_duration
    
    if not name_match:
        _EVALUATOR.logger.info(f"转场名称不匹配: 期望={expected_name}, 实际={transition_name}")
    if not duration_match:
        _EVALUATOR.logger.info(f"转场持续时间不匹配: 期望={expected_duration}ms, 实际={duration_ms}ms")
        
    return name_match and duration_match

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: frida消息对象
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

    # 从frida消息中获取实际的payload
    if message.get("type") != "send":
        return None
    
    payload = message.get("payload", {})
    event_type = payload.get("type")
    
    if not event_type:
        return None

    # 处理转场执行事件
    if event_type == "transition_executed":
        transition_name = payload.get("transition_name")
        duration_ms = payload.get("duration_ms")
        success = payload.get("success", False)

        if not success:
            _EVALUATOR.logger.info("转场执行失败")
            return None

        # 检查配置是否符合要求
        if check_transition_config(transition_name, duration_ms):
            _EVALUATOR.update_metric("transition_configured", True)
            completion_time = time.time() - _START_TIME
            _EVALUATOR.update_metric("time_to_complete", completion_time)
            _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
            return "success"
        else:
            _EVALUATOR.logger.info("转场配置不符合要求，任务未完成")

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