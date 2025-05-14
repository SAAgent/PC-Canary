#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    payload = message.get("payload")
    if not payload or not isinstance(payload, dict):
        logger.error(message)
        return None

    event_type = payload["event"]
    logger.debug(f"receive: {event_type}")

    if event_type == "current_scene":
        logger.info("get current scene")
        expected_scene = task_parameter.get("scene", "")
        scene = payload.get("scene", "")
        print(f"expected_scene: {expected_scene}, scene: {scene}")
        if expected_scene == scene:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "successfully switch scene"},
            ]

    return None
