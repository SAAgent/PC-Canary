#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, Any, Optional, List

_EVENT_SUCCESS = "scene_json_path"
_PAYLOAD_SUCCESS = "path"


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    payload = message.get("payload")
    if not payload or not isinstance(payload, dict):
        logger.error(message)
        return None
    event_type = payload["event"]
    logger.debug(f"receive: {event_type}")
    if event_type == _EVENT_SUCCESS:
        logger.info(payload.get("message", ""))
        expected = task_parameter.get("new_scene_name", "")
        current = payload.get(_PAYLOAD_SUCCESS, "")
        with open(current, "r") as f:
            data = json.load(f)
            flag = False
            if "scene_order" in data and isinstance(data["scene_order"], list):
                for scene in data["scene_order"]:
                    if (
                        isinstance(scene, dict)
                        and "name" in scene
                        and scene["name"] == expected
                    ):
                        flag = True
            if not flag:
                return [
                    {"status": "key_step", "index": 1},
                    {"status": "success", "reason": "delete scene success"},
                ]

    return None
