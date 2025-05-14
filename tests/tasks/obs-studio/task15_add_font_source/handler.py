#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
from typing import Dict, Any, Optional, List

_EVENT_FUNCTION_RETURN = "function returned"

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"Received event: {event_type}")
    key_step = []
    if event_type == _EVENT_FUNCTION_RETURN:           
        function = payload.get('function', '')
        logger.info("Function returned: " + function)
        if function == "OBSBasic::Save":
            file = payload.get("file", "")
            logger.info("Scene file: " + file)
            if file and os.path.exists(file):
                with open(file, 'r') as f:
                    scene_data = json.load(f)
                    sources = scene_data.get('sources', [])
                    scene_name = task_parameter.get("scene_name", "")
                    # Check if the scene name exists
                    if scene_name:
                        for source in sources:
                            if source.get('name') == scene_name:
                                key_step.append({"status": "key_step", "index": 1})
                                logger.info("key step 1: Scene exists in the scene file")
                                # Check if the text source name exists in the items list of the settings dictionary in the scene
                                items = source.get('settings', {}).get('items', [])
                                for item in items:
                                    if item.get('name') == task_parameter.get("new_source_name", ""):
                                        key_step.append({"status": "key_step", "index": 2})
                                        logger.info("key step 2: Text source exists in the scene file")
                                        break
                                else:
                                    logger.error(f"Text source does not exist in scene {scene_name}")
                                    key_step.append({"status": "error", "message": f"Text source does not exist in scene {scene_name}"})
                                break
                        else:
                            logger.error(f"Scene {scene_name} does not exist")
                            key_step.append({"status": "error", "message": f"Scene {scene_name} does not exist"})
                    else:
                        logger.error("Scene name not provided")
                        key_step.append({"status": "error", "message": "Scene name not provided"})
                    # Check if the text source name exists
                    name = task_parameter.get("new_source_name", "")
                    for source in sources:
                        if source.get('name') == name:
                            source_settings = source.get('settings', {})
                            expected_settings = task_parameter.get("settings", {})
                            # Check if all settings in expected_settings exist in source_settings and match their values
                            is_match = True
                            for key, expected_value in expected_settings.items():
                                if key not in source_settings:
                                    is_match = False
                                    logger.error(f"Setting {key} does not exist")
                                    break
                                if source_settings[key] != expected_value:
                                    is_match = False
                                    logger.error(f"Setting {key} value does not match: expected {expected_value}, actual {source_settings[key]}")
                                    break
                                    
                            if is_match:
                                key_step.append({"status": "key_step", "index": 3})
                                logger.info("key step 3: Settings match in the scene file")
                                key_step.append({"status": "success", "reason": "Scene and text source match, settings successful"})
                                logger.info(f"Settings for text source {name} matched successfully")
                            else:
                                logger.error(f"Settings for text source {name} do not match")
                                logger.debug(f"Expected settings: {expected_settings}")
                                logger.debug(f"Actual settings: {source_settings}")

    return key_step
