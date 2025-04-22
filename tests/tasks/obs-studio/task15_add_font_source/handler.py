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

_MATCH_SUCCESS = False
_LOCKED_SUCCESS = False

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
    global _EVALUATOR, _CONFIG, _START_TIME, _MATCH_SUCCESS, _LOCKED_SUCCESS
    
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
                function = payload.get('function', '')
                _EVALUATOR.logger.info("函数返回: " + function)
                if function == "OBSBasic::Save":
                    file = payload.get("file", "")
                    if file:
                        try:
                            with open(file, 'r') as f:
                                scene_data = json.load(f)
                                sources = scene_data.get('sources', [])
                                name = _CONFIG.get("task_parameters", {}).get("new_source_name", "")
                                for source in sources:
                                    if source.get('name') == name:
                                        source_settings = source.get('settings', {})
                                        expected_settings = _CONFIG.get("task_parameters", {}).get("settings", {})
                                        # 检查expected_settings中的所有设置是否都在source_settings中，并且值完全匹配
                                        is_match = True
                                        for key, expected_value in expected_settings.items():
                                            if key not in source_settings:
                                                is_match = False
                                                _EVALUATOR.logger.error(f"设置项 {key} 不存在")
                                                break
                                            if source_settings[key] != expected_value:
                                                is_match = False
                                                _EVALUATOR.logger.error(f"设置项 {key} 的值不匹配: 期望 {expected_value}, 实际 {source_settings[key]}")
                                                break
                                                
                                        if is_match:
                                            _EVALUATOR.update_metric("settings_set_success", True)
                                            _MATCH_SUCCESS = True
                                            _EVALUATOR.logger.info(f"文本源 {name} 的设置匹配成功")
                                        else:
                                            _EVALUATOR.logger.error(f"文本源 {name} 的设置不匹配")
                                            _EVALUATOR.logger.debug(f"期望设置: {expected_settings}")
                                            _EVALUATOR.logger.debug(f"实际设置: {source_settings}")
                        except Exception as e:
                            _EVALUATOR.logger.error(f"读取场景文件失败: {str(e)}")

                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
                
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    
    if _MATCH_SUCCESS:
        _EVALUATOR.update_metric("success", True)
        completion_time = time.time() - _START_TIME
        _EVALUATOR.update_metric("time_to_complete", completion_time)
        _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
        return "success"

    return None

def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler
