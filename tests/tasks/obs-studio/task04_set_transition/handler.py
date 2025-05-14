#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message.get('payload')
    if not payload or not isinstance(payload, dict):
        logger.error(message)
        return None
    event_type = payload['event']
    if event_type == "current_transition":
        logger.info("get current transition")     
        expected_transition = task_parameter.get("transition", "")
        transition = payload.get('transition', '')
        print(f"expected_scene: {expected_transition}, transition: {transition}")
        if expected_transition == transition:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "successfully set transition"},
            ]
        
    return None