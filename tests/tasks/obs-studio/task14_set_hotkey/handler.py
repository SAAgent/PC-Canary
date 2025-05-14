#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

step = 0


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    global step
    payload = message["payload"]
    event_type = payload["event"]
    logger.debug(f"Received event: {event_type}")
    if event_type == "hotkey_press":
        name = payload.get("name", "")
        if name == "OBSBasic.StartRecording":
            if step == 2:
                return [
                    {"status": "key_step", "index": 3},
                    {
                        "status": "success",
                        "reason": "Successfully found the hotkey and triggered the test completion",
                    },
                ]

    elif event_type == "inject_hotkey":
        name = payload.get("name", "")
        if name == "OBSBasic.StartRecording":
            if step == 2:
                return [
                    {"status": "key_step", "index": 3},
                    {
                        "status": "success",
                        "reason": "Successfully found the hotkey and triggered the test completion",
                    },
                ]

    elif event_type == "set_hotkey_success":
        name = payload.get("name", "")
        print("set_hotkey_success: " + name)
        if name == "OBSBasic.StartRecording" or name == "OBSBasic.StopRecording":
            if step == 0:
                step = 1
                return [
                    {"status": "key_step", "index": 1},
                ]

    elif event_type == "save_success":
        file_path = payload.get("file", "")
        if not file_path:
            logger.error("Failed to get the configuration file path")
            return None
        logger.info(f"Configuration file path: {file_path}")

        try:
            import configparser

            config = configparser.ConfigParser()
            config.read(file_path)

            if not config.has_section("Hotkeys"):
                return [
                    {
                        "status": "error",
                        "reason": "script_error",
                        "message": "No hotkey configuration found in the configuration file",
                    },
                ]

            start_recording = config.get(
                "Hotkeys", "OBSBasic.StartRecording", fallback=""
            )
            stop_recording = config.get(
                "Hotkeys", "OBSBasic.StopRecording", fallback=""
            )

            if not start_recording or not stop_recording:
                return [
                    {
                        "status": "error",
                        "reason": "script_error",
                        "message": "No recording-related hotkey configuration found",
                    },
                ]

            import json

            start_bindings = json.loads(start_recording).get("bindings", [])
            stop_bindings = json.loads(stop_recording).get("bindings", [])

            if not start_bindings or not stop_bindings:
                return [
                    {
                        "status": "error",
                        "reason": "script_error",
                        "message": "Recording hotkey not bound",
                    },
                ]

            start_key = start_bindings[0]
            stop_key = stop_bindings[0]
            expected_key = task_parameter.get("hotkey", {})

            if start_key == expected_key and stop_key == expected_key:
                if step == 1:
                    step = 2
                    return [{"status": "key_step", "index": 2}]
            else:
                return [
                    {
                        "status": "error",
                        "reason": "script_error",
                        "message": "Incorrect hotkey configuration",
                    },
                ]

        except Exception as e:
            return [
                {
                    "status": "error",
                    "reason": "script_error",
                    "message": f"Error verifying hotkey configuration: {str(e)}",
                },
            ]

    return None
