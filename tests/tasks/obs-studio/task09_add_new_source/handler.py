#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, Any, Optional, List

_EVENT_SUCCESS = "scene_json_path"
_PAYLOAD_SUCCESS = "path"

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"receive: {event_type}")
    if event_type == _EVENT_SUCCESS:
        logger.info(payload.get("message", ""))     
        new = task_parameter.get("new_source_name", "")
        type = task_parameter.get("new_source_id", "")
        print(payload)
        current = payload.get(_PAYLOAD_SUCCESS, '')
        # 在json文件里面找是有名称为new并且类型是new_source_id的源
        with open(current, 'r') as f:
            data = json.load(f)
            flag = False             
            if 'sources' in data and isinstance(data['sources'], list):
                for scene in data['sources']:
                    if isinstance(scene, dict) and 'name' in scene and new == scene['name'] and type == scene['id']:
                        flag = True
            if (flag):
                return [
                    {"status": "key_step", "index": 1},
                    {"status": "success", "reason": "add source success"},
                ]
    return None
