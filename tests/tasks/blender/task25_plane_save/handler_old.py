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
                    "type": "Mesh",
                    "mesh_type": "Plane",
                    "modifier_type": "Bevel",
                    "file_dir": "/home/agent/blender-git",
                    "file_name": "Plane.blend"
                },

                "instruction_template": "在blender中增加一个${type}类型的${mesh_type},将其沿z轴下移2m,并对其进行增加${modifier_type}类型的Modifier后保存文件为${file_dir}/${file_name}.",

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
                    "element_added",
                    "element_moved",
                    "modifier_added",
                    "file_saved"
                ],
                "events": {
                    "element_added": "元素添加成功",
                    "element_moved": "元素移动成功",
                    "modifier_added": "Modifier添加成功",
                    "file_saved": "文件保存成功"
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
            
            elif event_type == "location_function_found":
                _EVALUATOR.logger.info(f"找到物体位置更改函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_location_function", True)

            elif event_type == "modifier_function_found":
                _EVALUATOR.logger.info(f"找到Modifier函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_modifier_function", True)
            
            elif event_type == "saveas_function_found":
                _EVALUATOR.logger.info(f"找到另存文件函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_saveas_function", True)
                
            elif event_type == "add_element_detected":
                query = payload.get("name", "")
                _EVALUATOR.logger.info(f"检测到新增元素: {query}")
                # 检查查询是否匹配预期
                expected_query = _CONFIG.get("mesh_type", "Plane")
                is_expected = query.lower() == expected_query.lower()
                if is_expected:
                    _EVALUATOR.logger.info("新增预期元素!")
                    _EVALUATOR.update_metric("correct_add", True)
            
            elif event_type == "add_element_finished":
                query = payload.get("success", False)

                if query:
                    _EVALUATOR.logger.info(f"检测到新增元素成功.")
                    _EVALUATOR.update_metric("success_add_element", True)
                else:
                    _EVALUATOR.logger.info(f"检测到新增元素失败.")
                    _EVALUATOR.update_metric("success_add_element", False)
            
            elif event_type == "add_modifier_detected":
                is_expected = payload.get("type", False)
                if is_expected:
                    _EVALUATOR.logger.info("选择Modifier成功!")
                    _EVALUATOR.update_metric("correct_select_modifier", True)
            
            elif event_type == "set_location_detected":
                location = payload.get("location", [])
                _EVALUATOR.logger.info(f"检测到位置设置: {location}")
                
                # 检查位置是否匹配预期
                expected_location = _CONFIG.get("location", [0, 0, -2])
                is_expected = location == expected_location
                if is_expected:
                    _EVALUATOR.logger.info("位置设置成功!")
                    _EVALUATOR.update_metric("correct_location_set", True)
            
            elif event_type == "add_modifier_finished":
                is_expected = payload.get("success", False)
                if is_expected:
                    _EVALUATOR.logger.info("添加Modifier成功!")
                    _EVALUATOR.update_metric("correct_add_modifier", True)

            elif event_type == "saveas_file_detected":
                query = payload.get("file_path", "")
                _EVALUATOR.logger.info(f"检测到另存文件: {query}")
                
                # 检查查询是否匹配预期
                expected_query = ('/').join([_CONFIG.get("file_dir", ""),_CONFIG.get("file_name","")])
                is_expected = query.lower() == expected_query.lower()
                if is_expected:
                    _EVALUATOR.logger.info("另存文件路径正确!")
                    _EVALUATOR.update_metric("saveas_path_correct", True)

            elif event_type == "saveas_file_finished":
                is_expected = payload.get("retval", False)
                if is_expected:
                    _EVALUATOR.logger.info("另存文件成功!")
                    _EVALUATOR.update_metric("correct_saveas", True)

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
