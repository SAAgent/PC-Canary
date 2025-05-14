#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message.get('payload')
    if not payload or not isinstance(payload, dict):
        logger.error(message)
        return None

    event_type = payload['event']
    if event_type == "obs_output_force_stop_returned" or event_type == "obs_output_stop_returned":                
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": "stop recording success"},
        ]

    return None