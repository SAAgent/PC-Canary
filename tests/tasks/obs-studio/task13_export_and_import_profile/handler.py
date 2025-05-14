#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from typing import Dict, Any, Optional, List

step = 0
config_path = ""


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    global step, config_path
    print(message)
    payload = message["payload"]
    event_type = payload["event"]
    logger.debug(f"Received event: {event_type}")
    if event_type == "export_success":
        export_path = task_parameter.get("export_path", "")
        profile_name = task_parameter.get("profile_name", "")
        expected_path = os.path.join(export_path, profile_name)
        if os.path.exists(expected_path):
            step = 1
            return [
                {"status": "key_step", "index": 1},
            ]
        else:
            return [
                {
                    "status": "error",
                    "reason": "script_error",
                    "message": "Cannot find the corresponding configuration file",
                },
            ]

    elif event_type == "import_success":
        import_path = task_parameter.get("import_path", "")
        have_dir = os.path.exists(import_path)
        success = (
            True if payload.get("import_success", "") == "True" else False
        ) and have_dir
        found_import = False
        if config_path.endswith("/*"):
            config_path = config_path[:-2]
        print(config_path)
        if os.path.exists(config_path):
            if os.path.basename(import_path) in os.listdir(config_path):
                print(os.path.basename(import_path))
                print(os.listdir(config_path))
                found_import = True
            else:
                for root, dirs, files in os.walk(config_path):
                    if os.path.basename(import_path) in dirs:
                        found_import = True
                        break
        if success and step == 1 and found_import:
            return [
                {"status": "key_step", "index": 2},
                {
                    "status": "success",
                    "reason": "Successfully imported configuration file",
                },
            ]

    elif event_type == "get_config_path":
        config_path = payload.get("path", "")

    return None
