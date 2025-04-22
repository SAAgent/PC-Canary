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

_TEST_SUCCESS = False
_SET_SUCCESS = False
_FOUND_SUCCESS = False

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
    global _EVALUATOR, _CONFIG, _START_TIME, _TEST_SUCCESS, _SET_SUCCESS, _FOUND_SUCCESS
    
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

            elif event_type == "hotkey_press":
                name = payload.get("name")
                if name == "OBSBasic.StartRecording":
                    _EVALUATOR.update_metric("test_hotkey_success", True)
                    _TEST_SUCCESS = True
            
            elif event_type == "set_hotkey_success":
                name = payload.get("name", "")
                print("set_hotkey_success: " + name)
                if name == "OBSBasic.StartRecording" or name == "OBSBasic.StopRecording":
                    _EVALUATOR.update_metric("set_hotkey_success", True)
                    _SET_SUCCESS = True
            
            elif event_type == "save_success":
                file_path = payload.get("file", "")
                if not file_path:
                    _EVALUATOR.logger.error("未获取到配置文件路径")
                    return None
                _EVALUATOR.logger.info(f"配置文件路径: {file_path}")
                
                try:
                    import configparser
                    config = configparser.ConfigParser()
                    config.read(file_path)
                    
                    if not config.has_section("Hotkeys"):
                        _EVALUATOR.logger.error("配置文件中不存在Hotkeys节")
                        return None
                        
                    start_recording = config.get("Hotkeys", "OBSBasic.StartRecording", fallback="")
                    stop_recording = config.get("Hotkeys", "OBSBasic.StopRecording", fallback="")
                    
                    if not start_recording or not stop_recording:
                        _EVALUATOR.logger.error("未找到录制相关的热键配置")
                        return None
                        
                    import json
                    start_bindings = json.loads(start_recording).get("bindings", [])
                    stop_bindings = json.loads(stop_recording).get("bindings", [])
                    
                    if not start_bindings or not stop_bindings:
                        _EVALUATOR.logger.error("录制热键未设置绑定")
                        _FOUND_SUCCESS = False
                        return None
                        
                    start_key = start_bindings[0].get("key", "")
                    stop_key = stop_bindings[0].get("key", "")
                    
                    if start_key == "OBS_KEY_R" and stop_key == "OBS_KEY_R":
                        _EVALUATOR.update_metric("found_success", True)
                        _FOUND_SUCCESS = True
                        _EVALUATOR.logger.info("热键配置验证成功")
                    else:
                        _EVALUATOR.logger.error("热键配置不正确")
                        
                except Exception as e:
                    _EVALUATOR.logger.error(f"验证热键配置时出错: {str(e)}")

                pass
                
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
                
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    
    if _TEST_SUCCESS and _SET_SUCCESS and _FOUND_SUCCESS:
        _EVALUATOR.update_metric("success", True)
        completion_time = time.time() - _START_TIME
        _EVALUATOR.update_metric("time_to_complete", completion_time)
        _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
        return "success"

    return None

def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler
