#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD事件处理器
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

# 函数相关常量
FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc"
ORIGIN_FUNCTION_NAME = "Document::saveToFile"
FUNCTION_BEHAVIOR = "保存文档"

# 事件类型常量
SCRIPT_INITIALIZED = "script_initialized"
FUNCTION_NOT_FOUND = "function_not_found"
FUNCTION_FOUND = "function_found"
FUNCTION_CALLED = "function_called"
FUNCTION_KEY_WORD_DETECTED = "funtion_key_word_detected"
ERROR = "error"
HOOK_INSTALLED = "hook_installed"

# 关键字相关常量
RADIUS = "radius"
HEIGHT = "height"
KEY_WORDS = [RADIUS, HEIGHT]

APP_NAME = "FreeCAD"

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
            _CONFIG = {"task_parameters": {RADIUS: 5, HEIGHT: 10}}

def execute_python_code(code: str) -> Dict[str, Any]:
    """
    执行Python代码并返回结果
    
    Args:
        code: 要执行的Python代码
        
    Returns:
        Dict[str, Any]: 执行结果
    """
    try:
        # 创建一个新的命名空间来执行代码
        namespace = {}
        exec(code, namespace)
        result = namespace.get('result', None)
        
        if result is None:
            _EVALUATOR.logger.warning("未找到立方体对象")
            return None
            
        # 验证结果格式
        required_keys = [RADIUS, HEIGHT]
        if not all(key in result for key in required_keys):
            _EVALUATOR.logger.error(f"结果缺少必要的键: {required_keys}")
            return None
            
        return result
    except Exception as e:
        _EVALUATOR.logger.error(f"执行Python代码时出错: {str(e)}")
        return None

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
            if event_type == SCRIPT_INITIALIZED:
                _EVALUATOR.logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == FUNCTION_FOUND:
                _EVALUATOR.logger.info(f"找到函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric(FUNCTION_FOUND, True)
                
            elif event_type == FUNCTION_CALLED: 
                _EVALUATOR.logger.info(f"函数被调用: {payload.get('message', '')}")
                _EVALUATOR.update_metric(FUNCTION_CALLED, True)
                
            elif event_type == FUNCTION_KEY_WORD_DETECTED:
                try:
                    # 执行Python代码并获取结果
                    code = payload.get('code', '')
                    filename = payload.get('filename', '')
                    expected_path = _CONFIG.get("task_parameters", {}).get("source_path", "") + _CONFIG.get("task_parameters", {}).get("filename", "")
                    _EVALUATOR.logger.info(f"检测到关键字，文档路径: {{{filename}}}, 预期文档路径: {{{expected_path}}}")
                    if filename == expected_path:
                        result = execute_python_code(code)
                        expected_radius = _CONFIG.get("task_parameters", {}).get(RADIUS, 5)
                        expected_height = _CONFIG.get("task_parameters", {}).get(HEIGHT, 10)

                        actual_radius = result.get(RADIUS, 0)
                        actual_height = result.get(HEIGHT, 0)

                        _EVALUATOR.logger.info(f"预期尺寸: π{expected_radius}^2x{expected_height}, 实际尺寸: {actual_radius}x{actual_height}")

                        if (actual_radius == expected_radius and 
                            actual_height == expected_height):
                            _EVALUATOR.update_metric(FUNCTION_KEY_WORD_DETECTED, True)
                            _EVALUATOR.update_metric("success", True)
                            completion_time = time.time() - _START_TIME
                            _EVALUATOR.update_metric("time_to_complete", completion_time)
                            
                            _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
                                
                            return "success"
                except Exception as e:
                    _EVALUATOR.logger.error(f"出错: {str(e)}")
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