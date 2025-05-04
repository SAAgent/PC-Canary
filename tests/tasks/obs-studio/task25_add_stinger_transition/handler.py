#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OBS Studio 添加 Stinger 过渡并演示切换
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional

_EVALUATOR = None
_CONFIG = None
_START_TIME = None

# 任务成功条件的追踪状态
_STINGER_CREATED = False
_STINGER_CONFIGURED = False
_STINGER_USED = False

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator

    # 使用评估器的已更新配置，而不是重新读取文件
    if hasattr(evaluator, "config") and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("使用评估器中的更新配置")
    else:
        # 作为备份，如果评估器中没有配置，才从文件读取
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "config.json")

            with open(config_file, "r") as f:
                _CONFIG = json.load(f)
                _EVALUATOR.logger.info("从文件加载配置")
        except Exception as e:
            if _EVALUATOR:
                _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")
            # 提供一个默认配置以避免空引用
            _CONFIG = {
                "task_id": "25", 
                "task_name": "add_stinger_transition",
                "description": "添加 Stinger 过渡并演示切换",
                "task_parameters": {
                    "stinger_file": "271161_small.mp4",
                    "transition_point_ms": 300
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
    global _EVALUATOR, _CONFIG, _START_TIME, _STINGER_CREATED, _STINGER_CONFIGURED, _STINGER_USED
    
    # 初始化开始时间
    if _START_TIME is None:
        _START_TIME = time.time()
    
    # 检查评估器是否已设置
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None
        
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        if 'event' in payload:
            event_type = payload['event']
            _EVALUATOR.logger.debug(f"接收到事件: {event_type}")
            
            _EVALUATOR.record_event(event_type, payload)
            
            if event_type == "script_initialized":
                _EVALUATOR.logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == "function_found":
                _EVALUATOR.logger.info(f"找到函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_function", True)
                
            elif event_type == "hook_installed":
                _EVALUATOR.logger.info(f"钩子安装完成: {payload.get('message', '')}")
                
            # Stinger过渡创建相关事件
            elif event_type == "createStingerTransition_called":
                _EVALUATOR.logger.info("拦截到创建Stinger过渡函数调用")
                
            elif event_type == "createStingerTransition_returned":
                _EVALUATOR.logger.info("创建Stinger过渡函数返回")
                
            elif event_type == "stinger_transition_created":
                _EVALUATOR.logger.info("Stinger过渡已创建")
                _STINGER_CREATED = True
                _EVALUATOR.update_metric("stinger_transition_created", True)
                
            # Stinger过渡配置相关事件
            elif event_type == "configureStingerTransition_called":
                _EVALUATOR.logger.info("拦截到配置Stinger过渡函数调用")
                
            elif event_type == "configureStingerTransition_returned":
                _EVALUATOR.logger.info("配置Stinger过渡函数返回")
                expected_file = _CONFIG.get("task_parameters", {}).get("stinger_file", "")
                expected_transition_point = _CONFIG.get("task_parameters", {}).get("transition_point_ms", 0)
                file = payload.get("file")
                try:
                    with open(file, "r") as f:
                        data = json.load(f)
                        transitions = data.get("transitions", [])
                        for transition in transitions:
                            if transition.get("id") == "obs_stinger_transition":
                                transition_point = transition.get("settings", {}).get("transition_point", 0)
                                transition_file = transition.get("settings", {}).get("path", "")

                                if transition_point == expected_transition_point and transition_file == expected_file:
                                    _EVALUATOR.logger.info("Stinger过渡配置文件验证成功: transition_point为300")
                                    _STINGER_CONFIGURED = True
                                    _EVALUATOR.update_metric("stinger_transition_configured", True)
                                else:
                                    _EVALUATOR.logger.warning(f"Stinger过渡配置文件验证失败: transition_point为{transition_point}, 期望值为300")
                except Exception as e:
                    _EVALUATOR.logger.error(f"读取或解析配置文件失败: {str(e)}")
    
            # 场景切换相关事件
            elif event_type == "setTransition_called":
                _EVALUATOR.logger.info("拦截到设置过渡函数调用")
                
            elif event_type == "setTransition_returned":
                _EVALUATOR.logger.info("设置过渡函数返回")
                
            elif event_type == "sceneSwitch_called":
                _EVALUATOR.logger.info("拦截到场景切换函数调用")
                
            elif event_type == "sceneSwitch_returned":
                _EVALUATOR.logger.info("场景切换函数返回")
                
            elif event_type == "stinger_transition_used":
                _EVALUATOR.logger.info("Stinger过渡已使用")
                _STINGER_USED = True
                _EVALUATOR.update_metric("stinger_transition_used", True)
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})

            # 检查任务是否完成
            if _STINGER_CREATED and _STINGER_CONFIGURED and _STINGER_USED:
                # 标记任务成功并计算完成时间
                _EVALUATOR.update_metric("success", True)
                completion_time = time.time() - _START_TIME
                _EVALUATOR.update_metric("time_to_complete", completion_time)
                _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
                return "success"
                
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