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
                    "view_type": 5,
                    "type": "Text",
                    "object_mode": 1,
                    "text": "Blender"
                },

                "instruction_template": "在blender中中切换为top视图，新增文本后切换为编辑视图，将文本编辑为${text}.",

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
                    "view_changed",
                    "element_added",
                    "object_mode_changed",
                    "text_changed"
                ],
                "events": {
                    "view_changed": "视图切换成功",
                    "element_added": "元素添加成功",
                    "object_mode_changed": "更改视图模式成功",
                    "text_changed": "文本编辑成功"
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
                
            elif event_type == "add_function_found":
                _EVALUATOR.logger.info(f"找到新增函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_add_function", True)

            elif event_type == "view_function_found":
                _EVALUATOR.logger.info(f"找到切换viewpoint函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("view_select_function", True)
            
            elif event_type == "edit_function_found":
                _EVALUATOR.logger.info(f"找到切换编辑模式函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_edit_function", True)
            
            elif event_type == "text_function_found":
                _EVALUATOR.logger.info(f"找到编辑文本函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_text_function", True)
            
            elif event_type == "view_change_detected":
                query = payload.get("type", 0)
                _EVALUATOR.logger.info(f"检测到切换viewpoint")
                # 检查查询是否匹配预期
                expected_query =  _CONFIG.get("type", 0)
                is_expected = query == expected_query
                if is_expected:
                    _EVALUATOR.logger.info("目标viewpoint类型正确!")
                    _EVALUATOR.update_metric("correct_view_type", True)
            
            elif event_type == "view_change_finished":
                is_expected = payload.get("success", False)
                if is_expected:
                    _EVALUATOR.logger.info("切换viewpoint成功!")
                    _EVALUATOR.update_metric("correct_change_view", True)
                
            elif event_type == "add_element_detected":
                is_expected = payload.get("success", False)
                _EVALUATOR.logger.info(f"检测到新增Text元素")
                if is_expected:
                    _EVALUATOR.logger.info("新增预期元素成功!")
                    _EVALUATOR.update_metric("correct_add", True)
                else:
                    _EVALUATOR.logger.info(f"新增预期元素失败.")
                    _EVALUATOR.update_metric("correct_add", False)
            
            elif event_type == "change_mode_detected":
                query = payload.get("object_mode", 0)
                _EVALUATOR.logger.info(f"检测到更改视图模式为: {query}")

                expected_query = _CONFIG.get("object_mode", 1)
                # 检查查询是否匹配预期
                is_expected = query == expected_query
                if is_expected:
                    _EVALUATOR.logger.info("更改视图模式为编辑模式.")
                    _EVALUATOR.update_metric("correct_change_mode", True)
            
            elif event_type == "change_mode_finished":
                # 检查查询是否匹配预期
                is_expected = payload.get("success", False)
                if is_expected:
                    _EVALUATOR.logger.info("更改视图模式为编辑模式成功.")

            elif event_type == "change_text_detected":
                query = payload.get("text", "")
                _EVALUATOR.logger.info(f"检测到编辑文本")
                
                # 检查查询是否匹配预期
                expected_query = _CONFIG.get("text", "Blender")
                is_expected = query.lower() == expected_query.lower()
                if is_expected:
                    # 标记任务成功并计算完成时间
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
