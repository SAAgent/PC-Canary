#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    payload = message["payload"]
    print(payload)
    event_type = payload["event"]
    logger.debug(f"Received event: {event_type}")

    # Handle image source added event
    if event_type == "image_source_added":
        source_name = payload.get("source_name")
        image_path = payload.get("image_path")

        if (
            source_name == task_parameter["source_name"]
            and image_path == task_parameter["image_path"]
        ):
            logger.info("Image source added successfully")
            return [
                {"status": "key_step", "index": 1},
            ]

    # Handle opacity set event
    elif event_type == "opacity_set":
        source_name = payload.get("source_name")
        opacity = payload.get("opacity")
        print(opacity)
        print(task_parameter["opacity"])
        print(opacity == task_parameter["opacity"])
        if (
            source_name == task_parameter["source_name"]
            and opacity == task_parameter["opacity"]
        ):
            logger.info("Opacity set successfully")
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": "Opacity set successfully"},
            ]

    # Handle filter added event
    elif event_type == "filter_added":
        source_name = payload.get("source_name")
        filter_id = payload.get("filter_id")
        opacity = payload.get("opacity")
        if (
            source_name == task_parameter["source_name"]
            and filter_id == task_parameter["filter_id"]
            and opacity == task_parameter["opacity"]
        ):
            logger.info("Filter added successfully")
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": "Filter added successfully"},
            ]

    return None
