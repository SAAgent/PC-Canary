#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

_DELETED_SOURCES = set()  # Used to track deleted sources

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"Received event: {event_type}")
    # Handle source deletion event
    if event_type == "source_deleted":
        source_name = payload.get("source_name")
        if source_name in task_parameter["source_names"]:
            _DELETED_SOURCES.add(source_name)
            logger.info(f"Source {source_name} has been deleted")
            
            # Check if all required sources have been deleted
            if _DELETED_SOURCES == set(task_parameter["source_names"]):
                return [
                    {"status": "key_step", "index": 1},
                    {"status": "success", "reason": "Successfully deleted color sources"},
                ]

    return None
