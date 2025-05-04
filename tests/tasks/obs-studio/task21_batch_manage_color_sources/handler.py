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
_EVENT_SUCCESS = "scene_json_path"
_PAYLOAD_SUCCESS = "path"

def set_evaluator(evaluator):
    global _EVALUATOR, _CONFIG, _EVENT_SUCCESS, _PAYLOAD_SUCCESS
    _EVALUATOR = evaluator
    if hasattr(evaluator, "config") and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("使用评估器中的更新配置")
    else:
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "config.json")
            with open(config_file, "r") as f:
                _CONFIG = json.load(f)
                _EVALUATOR.logger.info("从文件加载配置")
        except Exception as e:
            if _EVALUATOR:
                _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")
            _CONFIG = {}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    global _EVALUATOR, _CONFIG, _START_TIME
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
            elif event_type == _EVENT_SUCCESS:
                _EVALUATOR.logger.info(payload.get("message", ""))
                scene_name = _CONFIG.get("task_parameters", {}).get("scene_name", "")
                add_sources = _CONFIG.get("task_parameters", {}).get("add_color_sources", [])
                reorder_to = _CONFIG.get("task_parameters", {}).get("reorder_to", [])
                delete_sources = _CONFIG.get("task_parameters", {}).get("delete_sources", [])
                current_file_path = payload.get(_PAYLOAD_SUCCESS, '')
                try:
                    with open(current_file_path, 'r') as f:
                        data = json.load(f)

                        # 检查场景中的纯色源顺序和删除情况
                        scene_items = data.get('sources', [])
                        for scene_item in scene_items:
                            if scene_item.get('name') == scene_name:
                                settings_items = scene_item.get('settings', {}).get('items', [])
                                settings_items_name = [item.get('name') for item in settings_items]
                                print(settings_items_name)
                                matched_items = [item.get('name') for item in settings_items if item.get('name') in add_sources]
                                expected_final = [name for name in reorder_to if name not in delete_sources]
                                print(matched_items)
                                print(expected_final)
                                if matched_items == expected_final:
                                    _EVALUATOR.update_metric("success", True)
                                    completion_time = time.time() - _START_TIME
                                    _EVALUATOR.update_metric("time_to_complete", completion_time)
                                    _EVALUATOR.logger.info(f"任务成功完成! 最终纯色源顺序: {matched_items}")
                                    _EVALUATOR.logger.info(f"耗时: {completion_time:.2f} 秒")
                                    return "success"
                                else:
                                    _EVALUATOR.logger.info(f"当前纯色源顺序: {matched_items}，期望: {expected_final}")
                        _EVALUATOR.logger.info(f"未找到场景 {scene_name}")
                except Exception as e:
                    _EVALUATOR.logger.error(f"检查配置文件时发生错误: {str(e)}")
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    return None

def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler 