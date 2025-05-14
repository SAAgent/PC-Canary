#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List
import json

_EVENT_SUCCESS = "scene_json_path"
_PAYLOAD_SUCCESS = "path"


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    payload = message["payload"]
    event_type = payload["event"]
    logger.debug(f"receive: {event_type}")
    if event_type == _EVENT_SUCCESS:
        logger.info(payload.get("message", ""))
        old = task_parameter.get("old_scene_name", "")
        new = task_parameter.get("new_scene_name", "")
        print(payload)
        current = payload.get(_PAYLOAD_SUCCESS, "")
        # 在json文件里面找是否old不存在并且new存在
        with open(current, "r") as f:
            data = json.load(f)
            flag_old = False
            flag_new = False
            if "scene_order" in data and isinstance(data["scene_order"], list):
                for scene in data["scene_order"]:
                    if (
                        isinstance(scene, dict)
                        and "name" in scene
                        and scene["name"] == old
                    ):
                        flag_old = True
                    if (
                        isinstance(scene, dict)
                        and "name" in scene
                        and scene["name"] == new
                    ):
                        flag_new = True
            if not flag_old and flag_new:
                return [
                    {"status": "key_step", "index": 1},
                    {"status": "success", "reason": "rename scene success"},
                ]
    return None
