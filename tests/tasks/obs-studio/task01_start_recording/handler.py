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

    event_type = payload.get("event")
    logger.info(payload.get("message", ""))

    if event_type == "is_recording_active":
        recording = payload.get("recording", False)
        logger.info(f"The recording state of obs is {recording}")

        if recording:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "start recording success"},
            ]

    return None
