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
            _CONFIG = {
                "task_parameters": {   
                    "name": "Ground",
                    "X": 6.0,
                    "Y": 6.0,
                    "Z": 6.0
                },

                "instruction_template": "在blender中修改已有Metaball类型的Cube元素的名称为${name}, 大小为${X}*${Y}*${Z}.",

                "evaluation_setup": {    
                    "scripts": [    
                        { "role": "hook",    "path": "hooker.js" },
                        { "role": "handler", "path": "handler.py" }
                    ],
                    "timeout": 120,    
                    "evaluator_type": "IpcInjector",
                    "evaluate_on_completion": false
                },
                "success_conditions": [ 
                    "element_renamed",
                    "element_resized"
                ],
                "events": {
                    "element_renamed":"元素重命名成功",
                    "element_resized":"元素大小修改成功"
                }      
            }

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
    
    # 处理消息
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        # 检查是否包含事件类型
        if 'event' in payload:
            event_type = payload['event']
            _EVALUATOR.logger.debug(f"接收到事件: {event_type}")
            
            # 记录事件
            _EVALUATOR.record_event(event_type, payload)
            
            # 处理特定事件
            if event_type == "script_initialized":
                _EVALUATOR.logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
            
            elif event_type == "rename_function_found":
                _EVALUATOR.logger.info(f"找到元素重命名函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_rename_function", True)
            
            elif event_type == "resize_function_found":
                _EVALUATOR.logger.info(f"找到元素大小修改函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_resize_function", True)
                
            elif event_type == "rename_element_detected":
                query = payload.get("name", "")
                expected_query = _CONFIG.get("name", "Ground")
                is_expected = query.lower() == expected_query.lower()
                if is_expected:
                    _EVALUATOR.logger.info("元素重命名名称为预期名称!")
                    _EVALUATOR.update_metric("correct_name", True)

            elif event_type == "rename_element_finished":
                is_expected = payload.get("success", False)
                if is_expected:
                    _EVALUATOR.logger.info("元素重命名成功!")
                    # 标记任务成功并计算完成时间
                    _EVALUATOR.update_metric("correct_rename", True)
            
            elif event_type == "resize_element_detected":
                X = payload.get("X", 0.0)
                Y = payload.get("Y", 0.0)
                Z = payload.get("Z", 0.0)
                expected_X = _CONFIG.get("X", 6.0)
                expected_Y = _CONFIG.get("Y", 6.0)
                expected_Z = _CONFIG.get("Z", 6.0)
                is_expected = abs(X - expected_X) < 0.01 and abs(Y - expected_Y) < 0.01 and abs(Z - expected_Z) < 0.01
                if is_expected:
                    _EVALUATOR.logger.info("元素大小修改为预期大小!")
                    _EVALUATOR.update_metric("correct_resize", True)

                    _EVALUATOR.update_metric("success", True)
                    completion_time = time.time() - _START_TIME
                    _EVALUATOR.update_metric("time_to_complete", completion_time)
                    
                    _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
                    
                    # 返回成功标志
                    return "success"
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
                
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    
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
