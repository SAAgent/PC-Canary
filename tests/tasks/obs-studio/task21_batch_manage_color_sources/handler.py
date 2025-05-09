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
_EVENT_SUCCESS = "scene_json_path"
_PAYLOAD_SUCCESS = "path"

key_steps = []

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global key_step
    print(message)
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    if event_type == _EVENT_SUCCESS:
        logger.info(payload.get("message", ""))
        scene_name = task_parameter.get("scene_name", "")
        add_sources = task_parameter.get("add_color_sources", [])
        reorder_to = task_parameter.get("reorder_to", [])
        delete_sources = task_parameter.get("delete_sources", [])
        current_file_path = payload.get(_PAYLOAD_SUCCESS, '')
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
                    if matched_items == add_sources:
                        if not dict_have_index(key_steps, 1):
                            key_steps.append({"status":"key_step", "index":1})
                            return [
                                {"status":"key_step", "index":1}
                            ]
                    if matched_items == reorder_to:
                        if not dict_have_index(key_steps, 2):
                            key_steps.append({"status":"key_step", "index":2})
                            return [
                                {"status":"key_step", "index":2}
                            ]
                    expected_final = [name for name in reorder_to if name not in delete_sources]
                    print(matched_items)
                    print(expected_final)
                    if matched_items == expected_final:
                        return [
                            {"status":"key_step", "index":3},
                            {"status":"success", "reason":"纯色源增加、重排、删除完成"}
                        ]
    return None

def dict_have_index(key_steps: Dict[str, Any], index: int) -> bool:
    for key_step in key_steps:
        if "index" in key_step and key_step["index"] == index:
            return True
    
    return False