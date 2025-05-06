#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, Any, Optional, List

_EVENT_SUCCESS = "updated_source"
_PAYLOAD_SUCCESS = "flag"

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    if event_type == "create_success":
        expected_scene_name = task_parameter.get("new_scene_name", "")
        expected_name = task_parameter.get("source_name", "")
        expected_type = task_parameter.get("source_type", "")
        source_name = payload.get("name", '')
        source_type = payload.get("type", '')
        if source_name == expected_scene_name:
            return [
                {"status": "key_step", "index": 1}
            ]
        if source_name == expected_name and source_type == expected_type:
            return [
                {"status": "key_step", "index": 2},
                {"status": "key_step", "index": 3}
            ]
    
    elif event_type == _EVENT_SUCCESS:
        logger.info(payload.get("message", ""))     
        
        if payload.get("looping", "") == "true":
            return [
                {"status": "key_step", "index": 4},
                {"status": "success", "reason": "成功添加循环媒体源"},
            ]
                
    return None
