#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, Any, Optional, List

_EVENT_SUCCESS = "scene_json_path"
_PAYLOAD_SUCCESS = "path"

key_steps = []


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    global key_steps
    print(message)
    payload = message["payload"]
    print(payload)
    event_type = payload["event"]
    logger.debug(f"Received event: {event_type}")
    if event_type == _EVENT_SUCCESS:
        logger.info(payload.get("message", ""))
        scene_name = task_parameter.get("scene_name", "")
        add_sources = task_parameter.get("add_color_sources", [])
        reorder_to = task_parameter.get("reorder_to", [])
        delete_sources = task_parameter.get("delete_sources", [])
        current_file_path = payload.get(_PAYLOAD_SUCCESS, "")
        with open(current_file_path, "r") as f:
            data = json.load(f)

            # Check the order and deletion status of color sources in the scene
            scene_items = data.get("sources", [])
            for scene_item in scene_items:
                if scene_item.get("name") == scene_name:
                    settings_items = scene_item.get("settings", {}).get("items", [])
                    matched_items = [
                        item.get("name")
                        for item in settings_items
                        if item.get("name") in add_sources
                    ]
                    if matched_items == add_sources:
                        if not dict_have_index(key_steps, 1):
                            key_steps.append({"status": "key_step", "index": 1})
                            return [{"status": "key_step", "index": 1}]
                    if matched_items == reorder_to:
                        if not dict_have_index(key_steps, 2):
                            key_steps.append({"status": "key_step", "index": 2})
                            return [{"status": "key_step", "index": 2}]
                    expected_final = [
                        name for name in reorder_to if name not in delete_sources
                    ]
                    print(matched_items)
                    print(expected_final)
                    if matched_items == expected_final:
                        return [
                            {"status": "key_step", "index": 3},
                            {
                                "status": "success",
                                "reason": "Color sources added, reordered, and deleted successfully",
                            },
                        ]
    return None


def dict_have_index(key_steps: List[Dict[str, Any]], index: int) -> bool:
    # Check if the key step with the given index exists in the list
    for key_step in key_steps:
        if "index" in key_step and key_step["index"] == index:
            return True

    return False
