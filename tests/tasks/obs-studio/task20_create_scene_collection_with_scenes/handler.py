#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, Any, Optional, List

_EVENT_FUNCTION_RETURN = "function returned"
_PAYLOAD_SUCCESS = "path"

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    print(message)
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"Received event: {event_type}")
    key_step = []
    if event_type == _EVENT_FUNCTION_RETURN:           
        logger.info("Function returned: " + payload.get('function', ''))
        current_file_path = payload.get(_PAYLOAD_SUCCESS, '')
        expected_collection = task_parameter.get("collection_name", "")
        expected_scenes = task_parameter.get("scene_names", [])
        # Check scene collection configuration file
        try:
            with open(current_file_path, 'r') as f:
                data = json.load(f)
                
                # Check scene collection name
                collection_name_found = False
                if ('name' in data and data['name'] == expected_collection):
                    collection_name_found = True
                    key_step.append({"status":"key_step", "index":1})
                
                # Check if scenes exist
                scenes_found = []
                if 'scene_order' in data and isinstance(data['scene_order'], list):
                    for scene in data['scene_order']:
                        if isinstance(scene, dict) and 'name' in scene:
                            for expected_scene in expected_scenes:
                                if scene['name'] == expected_scene and expected_scene not in scenes_found:
                                    scenes_found.append(expected_scene)
                
                # Determine if the task is completed
                if collection_name_found and len(scenes_found) == len(expected_scenes):
                    key_step.append({"status":"key_step", "index":2})
                    key_step.append({"status":"success","reason":"Scene collection name and scene list both matched successfully"})
                    return key_step
                # else:
                #     # Record incomplete cases
                #     if not collection_name_found:
                #         return [{"status": "error", "message": f"Specified scene collection not found: {expected_collection}"}]
                #     if len(scenes_found) == 0:
                #         return [{"status": "error", "message": f"None of the specified scenes found: {expected_scenes}"}]
                #     elif len(scenes_found) < len(expected_scenes):
                #         return [{"status": "error", "message": f"Some scenes not found, found: {scenes_found}, expected: {expected_scenes}"}]
        except Exception as e:
            return [
                {"status": "error", "message": f"Error occurred while checking configuration file: {str(e)}"}
            ]
    
    return None
