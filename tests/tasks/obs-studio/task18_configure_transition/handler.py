#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from typing import Dict, Any, Optional, List

def check_transition(transition_name: str, duration_ms: int, dest: str, logger, task_parameter) -> Optional[List[Dict[str, Any]]]:
    """检查转场配置是否符合要求"""
    expected_name = task_parameter["transition_name"]
    expected_duration = task_parameter["duration_ms"]
    expected_dest = task_parameter["dest"]
    
    name_match = transition_name == expected_name
    duration_match = duration_ms == expected_duration
    dest_match = dest == expected_dest
    
    key_step = []
    if name_match:
        key_step.append({"status": "key_step", "index": 1})

    if duration_match:
        key_step.append({"status": "key_step", "index": 2})
    
    if dest_match:
        key_step.append({"status": "key_step", "index":3})
        key_step.append({"status": "success", "reason": "name and duration matched"})
        
    return None if len(key_step) == 0 else key_step

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    print(message)
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")

    # 处理转场执行事件
    if event_type == "transition_executed":
        transition_name = payload.get("transition_name")
        duration_ms = payload.get("duration_ms")
        dest = payload.get("dest")

        return check_transition(transition_name, duration_ms, dest, logger, task_parameter)

    return None
