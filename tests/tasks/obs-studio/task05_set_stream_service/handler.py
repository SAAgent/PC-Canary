#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

_EVENT_SUCCESS = "current_stream_service"
_PAYLOAD_SUCCESS = "stream_service"

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message.get('payload')
    if not payload or not isinstance(payload, dict):
        logger.error(message)
        return None
    event_type = payload['event']
    logger.debug(f"receive: {event_type}")
    if event_type == _EVENT_SUCCESS:
        logger.info(payload.get("message", ""))     
        expected = task_parameter.get(_PAYLOAD_SUCCESS, "")
        current = payload.get(_PAYLOAD_SUCCESS, '')
        if expected == current:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "successfully set stream service"},
            ]
        
    if event_type == "obs_data_save_json_safe_returned":
        logger.info("successfully save json")
        logger.info(payload)
        json_path = payload.get("json", "")
        print(json_path)
        success = payload.get("success", "")
        if success == "0x1":
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "successfully save json"},
            ]
                
    return None
