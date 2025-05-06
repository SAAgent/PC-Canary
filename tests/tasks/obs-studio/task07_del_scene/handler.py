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

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    if event_type == _EVENT_SUCCESS:
        logger.info(payload.get("message", ""))     
        expected = task_parameter.get("new_scene_name", "")
        current = payload.get(_PAYLOAD_SUCCESS, '')
        with open(current, 'r') as f:
            data = json.load(f)
            flag = False                
            if 'scene_order' in data and isinstance(data['scene_order'], list):
                for scene in data['scene_order']:
                    if isinstance(scene, dict) and 'name' in scene and scene['name'] == expected:
                        flag = True
            if (not flag):
                return [
                    {"status": "key_step", "index": 1},
                    {"status": "success", "reason": "删除场景成功"},
                ]
                
    return None
