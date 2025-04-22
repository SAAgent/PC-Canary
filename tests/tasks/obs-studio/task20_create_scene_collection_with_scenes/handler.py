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
_EVENT_SUCCESS = "collection_scenes_json_path"
_PAYLOAD_SUCCESS = "path"

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG, _EVENT_SUCCESS, _PAYLOAD_SUCCESS
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
                current_file_path = payload.get(_PAYLOAD_SUCCESS, '')
                expected_collection = _CONFIG.get("task_parameters", {}).get("collection_name", "")
                expected_scenes = _CONFIG.get("task_parameters", {}).get("scene_names", [])
                # 检查场景集合配置文件
                try:
                    with open(current_file_path, 'r') as f:
                        data = json.load(f)
                        
                        # 检查场景集合名称
                        collection_name_found = False
                        if ('name' in data and data['name'] == expected_collection):
                            collection_name_found = True
                        
                        # 检查场景是否存在
                        scenes_found = []
                        if 'scene_order' in data and isinstance(data['scene_order'], list):
                            for scene in data['scene_order']:
                                if isinstance(scene, dict) and 'name' in scene:
                                    for expected_scene in expected_scenes:
                                        if scene['name'] == expected_scene and expected_scene not in scenes_found:
                                            scenes_found.append(expected_scene)
                        
                        # 判断是否完成任务
                        if collection_name_found and len(scenes_found) == len(expected_scenes):
                            # 标记任务成功并计算完成时间
                            _EVALUATOR.update_metric("success", True)
                            completion_time = time.time() - _START_TIME
                            _EVALUATOR.update_metric("time_to_complete", completion_time)
                            _EVALUATOR.logger.info(f"任务成功完成! 找到场景集合: {expected_collection}, 找到场景: {scenes_found}")
                            _EVALUATOR.logger.info(f"耗时: {completion_time:.2f} 秒")
                            return "success"
                        else:
                            # 记录未完成的情况
                            if not collection_name_found:
                                _EVALUATOR.logger.info(f"未找到指定的场景集合: {expected_collection}")
                            if len(scenes_found) == 0:
                                _EVALUATOR.logger.info(f"未找到任何指定的场景: {expected_scenes}")
                            elif len(scenes_found) < len(expected_scenes):
                                _EVALUATOR.logger.info(f"部分场景未找到, 找到: {scenes_found}, 期望: {expected_scenes}")
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