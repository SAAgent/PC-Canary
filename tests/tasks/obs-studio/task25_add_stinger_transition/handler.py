#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, Any, Optional, List

# Task success condition tracking status
_STINGER_CREATED = False
_STINGER_CONFIGURED = False
_STINGER_USED = False

key_steps = []

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global key_steps
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"Received event: {event_type}")
    global _EVALUATOR, _CONFIG, _START_TIME, _STINGER_CREATED, _STINGER_CONFIGURED, _STINGER_USED
                
    if event_type == "stinger_transition_created":
        logger.info("Stinger transition has been created")
        _STINGER_CREATED = True
        if not dict_have_index(key_steps, 1):
            key_steps.append({"status": "key_step", "index": 1})

    # Events related to Stinger transition configuration
    elif event_type == "configureStingerTransition_called":
        logger.info("Intercepted call to configure Stinger transition function")
        
    elif event_type == "configureStingerTransition_returned":
        logger.info("Configure Stinger transition function returned")
        expected_file = task_parameter.get("stinger_file", "")
        expected_transition_point = task_parameter.get("transition_point_ms", 0)
        file = payload.get("file")
        try:
            with open(file, "r") as f:
                data = json.load(f)
                transitions = data.get("transitions", [])
                for transition in transitions:
                    if transition.get("id") == "obs_stinger_transition":
                        transition_point = transition.get("settings", {}).get("transition_point", 0)
                        transition_file = transition.get("settings", {}).get("path", "")

                        if transition_point == expected_transition_point and transition_file == expected_file:
                            logger.info("Stinger transition configuration file validation succeeded: transition_point is 300")
                            _STINGER_CONFIGURED = True
                            if not dict_have_index(key_steps, 2):
                                key_steps.append({"status": "key_step", "index": 2})
                        else:
                            logger.warning(f"Stinger transition configuration file validation failed: transition_point is {transition_point}, expected value is 300")
        except Exception as e:
            logger.error(f"Failed to read or parse configuration file: {str(e)}")

    elif event_type == "stinger_transition_used":
        logger.info("Stinger transition has been used")
        _STINGER_USED = True
        if not dict_have_index(key_steps, 3):
            key_steps.append({"status": "key_step", "index": 3})

    # Check if the task is completed
    if _STINGER_CREATED and _STINGER_CONFIGURED and _STINGER_USED:
        key_steps.append({"status": "success", "reason": "All settings have been successfully completed"})
        return key_steps
    
    return None

def dict_have_index(key_steps: List[Dict[str, Any]], index: int) -> bool:
    for key_step in key_steps:
        if "index" in key_step and key_step["index"] == index:
            return True
    
    return False