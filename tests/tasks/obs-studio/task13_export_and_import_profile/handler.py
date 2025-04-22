#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
from typing import Dict, Any, Optional

_EVALUATOR = None
_CONFIG = None
_START_TIME = None

_EVENT_FUNCTION_CALL = "function called"
_EVENT_FUNCTION_RETURN = "function returned"

_IMPORT_SUCCESS = False
_EXPORT_SUCCESS = False

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
            _CONFIG = {}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    global _EVALUATOR, _CONFIG, _START_TIME, _IMPORT_SUCCESS, _EXPORT_SUCCESS
    
    if _START_TIME is None:
        _START_TIME = time.time()
    
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
                
            elif event_type == _EVENT_FUNCTION_CALL:
                _EVALUATOR.logger.info("拦截到函数调用: " + payload.get('function', ''))
                
            elif event_type == _EVENT_FUNCTION_RETURN:           
                _EVALUATOR.logger.info("函数返回: " + payload.get('function', ''))

            elif event_type == "export_success":
                export_path = _CONFIG.get("task_parameters", {}).get("export_path", "")
                profile_name = _CONFIG.get("task_parameters", {}).get("profile_name", "")
                expected_path = os.path.join(export_path, profile_name)
                if os.path.exists(expected_path):
                    _EVALUATOR.update_metric("export_success", True)
                    _IMPORT_SUCCESS = True
                    _EVALUATOR.logger.info(f"配置文件导出成功: {expected_path}")
                else:
                    _EVALUATOR.update_metric("export_success", False)
                    _EVALUATOR.logger.error(f"配置文件导出失败: {expected_path} 不存在")
            
            elif event_type == "import_success":
                import_path = _CONFIG.get("task_parameters", {}).get("import_path", "")
                have_dir = os.path.exists(import_path)
                if have_dir:
                    _EVALUATOR.logger.info(f"找到要导入的配置文件目录: {import_path}")
                else:
                    _EVALUATOR.logger.error(f"未找到要导入的配置文件目录: {import_path}")
                success = (True if payload.get("import_success", "") == "True" else False) and have_dir
                _EVALUATOR.update_metric("import_success", success)
                _EXPORT_SUCCESS = True
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
                
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    
    if _IMPORT_SUCCESS and _EXPORT_SUCCESS:
        _EVALUATOR.update_metric("success", True)
        completion_time = time.time() - _START_TIME
        _EVALUATOR.update_metric("time_to_complete", completion_time)
        _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
        return "success"

    return None

def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler
