#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

_EVENT_SET_VISIBLE_SUCCESS = "set_visible_success"
_PAYLOAD_SUCCESS = "flag"


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    payload = message["payload"]
    event_type = payload["event"]
    logger.debug(f"receive: {event_type}")
    if event_type == _EVENT_SET_VISIBLE_SUCCESS:
        logger.info(payload.get("message", ""))
        expected = task_parameter.get("source_name", "")
        expected_visible = task_parameter.get("source_visible")
        flag = payload.get(_PAYLOAD_SUCCESS)
        current = payload.get("source_name", "")
        visible = True if payload.get("visible") == 1 else False
        if flag and (current == expected) and (visible == expected_visible):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "successfully set source visibility"},
            ]
    return None
