#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
from typing import Dict, Any, Optional, List

_EVALUATOR = None
_CONFIG = None
_START_TIME = None

_EVENT_FUNCTION_CALL = "function called"
_EVENT_FUNCTION_RETURN = "function returned"
_EVENT_SUCCESS = "collection_scenes_json_path"
_PAYLOAD_SUCCESS = "path"

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    print(message)
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    key_step = []
    if event_type == _EVENT_FUNCTION_RETURN:           
        logger.info("函数返回: " + payload.get('function', ''))
        current_file_path = payload.get(_PAYLOAD_SUCCESS, '')
        expected_collection = task_parameter.get("collection_name", "")
        expected_scenes = task_parameter.get("scene_names", [])
        # 检查场景集合配置文件
        try:
            with open(current_file_path, 'r') as f:
                data = json.load(f)
                
                # 检查场景集合名称
                collection_name_found = False
                if ('name' in data and data['name'] == expected_collection):
                    collection_name_found = True
                    key_step.append({"status":"key_step", "index":1})
                
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
                    key_step.append({"status":"key_step", "index":2})
                    key_step.append({"status":"success","reason":"场景集合名称和场景列表都匹配成功"})
                    return key_step
                # else:
                #     # 记录未完成的情况
                #     if not collection_name_found:
                #         return [{"status": "error", "message": f"未找到指定的场景集合: {expected_collection}"}]
                #     if len(scenes_found) == 0:
                #         return [{"status": "error", "message": f"未找到任何指定的场景: {expected_scenes}"}]
                #     elif len(scenes_found) < len(expected_scenes):
                #         return [{"status": "error", "message": f"部分场景未找到, 找到: {scenes_found}, 期望: {expected_scenes}"}]
        except Exception as e:
            return [
                {"status": "error", "message": f"检查配置文件时发生错误: {str(e)}"}
            ]
    
    return None
