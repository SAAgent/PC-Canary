#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, Any, Optional, List

_EVENT_SUCCESS = "config_save"


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    payload = message["payload"]
    event_type = payload["event"]
    logger.debug(f"Received event: {event_type}")

    if event_type == "create_success":
        expected_scene = task_parameter.get("new_scene_name", "")
        expected_name = task_parameter.get("source_name", "")
        expected_type = task_parameter.get("source_type", "")
        source_name = payload.get("name", "")
        source_type = payload.get("type", "")
        if source_name == expected_scene:
            return [{"status": "key_step", "index": 1}]
        if source_name == expected_name and source_type == expected_type:
            return [
                {"status": "key_step", "index": 2},
                {"status": "key_step", "index": 3},
            ]

    elif event_type == _EVENT_SUCCESS:
        exp_width = task_parameter.get("width", 0)
        exp_height = task_parameter.get("height", 0)
        exp_name = task_parameter.get("source_name", "")
        logger.info(payload.get("message", ""))
        file_path = payload.get("path", "")
        with open(file_path, "r") as f:
            file_content = json.load(f)
            sources = file_content.get("sources", [])
            for source in sources:
                if source.get("name", "") == exp_name:
                    settings = source.get("settings", {})
                    width = settings.get("width", 0)
                    height = settings.get("height", 0)
                    if width == exp_width and height == exp_height:
                        return [
                            {"status": "key_step", "index": 4},
                            {
                                "status": "success",
                                "reason": "Successfully added color background source",
                            },
                        ]
                    else:
                        logger.info(
                            f"Resolution mismatch: width={width}, height={height}"
                        )
    return None
