#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from typing import Dict, Any, Optional, List
from PIL import Image

save_path = None
screenshot_called = False
screenshot_success = False


def verify_screenshot_path(
    save_path: str, logger, task_parameter
) -> List[Dict[str, Any]]:
    """Verify if the screenshot save path meets the requirements"""
    try:
        expected_path = task_parameter["save_path"]
        print(os.path.dirname(save_path))
        print(expected_path)
        # Check if the path matches
        if expected_path.rstrip("/") != os.path.dirname(save_path):
            logger.error(
                f"Screenshot save path does not match: Expected {expected_path}, Actual {save_path}"
            )
            return [
                {
                    "status": "error",
                    "message": f"Screenshot save path does not match: Expected {expected_path}, Actual {save_path}",
                }
            ]

        # Check if the file exists
        if not os.path.exists(save_path):
            logger.error(f"Screenshot file does not exist: {save_path}")
            return [
                {
                    "status": "error",
                    "message": f"Screenshot file does not exist: {save_path}",
                }
            ]

        return [{"status": "key_step", "index": 1}]
    except Exception as e:
        logger.error(f"Error occurred while verifying screenshot path: {e}")
        return [
            {
                "status": "error",
                "message": f"Error occurred while verifying screenshot path: {e}",
            }
        ]


def verify_screenshot_size(
    save_path: str, logger, task_parameter
) -> List[Dict[str, Any]]:
    """Verify if the screenshot size meets the requirements"""
    try:
        with Image.open(save_path) as img:
            width, height = img.size
            expected_width = task_parameter["width"]
            expected_height = task_parameter["height"]

            if width != expected_width or height != expected_height:
                logger.error(
                    f"Screenshot size does not match: Expected {expected_width}x{expected_height}, "
                    f"Actual {width}x{height}"
                )
                return [
                    {
                        "status": "error",
                        "message": f"Screenshot size does not match: Expected {expected_width}x{expected_height}, Actual {width}x{height}",
                    }
                ]

            return [
                {"status": "key_step", "index": 2},
                {
                    "status": "success",
                    "reason": "Screenshot path and size both match successfully",
                },
            ]
    except Exception as e:
        logger.error(f"Error occurred while verifying screenshot size: {e}")
        return [
            {
                "status": "error",
                "message": f"Error occurred while verifying screenshot size: {e}",
            }
        ]


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    global save_path, screenshot_called, screenshot_success
    payload = message["payload"]
    print(payload)
    event = payload["event"]
    logger.debug(f"Received event: {event}")
    key_step = []

    # Handle function call event
    if event == "function called" and payload.get("function") == "OBSBasic::Screenshot":
        screenshot_called = True
        logger.info("Detected screenshot function call")
        return None

    # Handle function return event
    if (
        event == "function returned"
        and payload.get("function") == "OBSBasic::Screenshot"
    ):
        screenshot_success = payload.get("success", False)
        if not screenshot_success:
            logger.error("Screenshot function execution failed")
        return None

    # Handle event to get save path
    if event == "screenshot_getpath":
        save_path = payload.get("save_path")
        if not save_path:
            logger.error("Failed to get screenshot save path")
            return None
        logger.info(f"Screenshot save path obtained: {save_path}")

    # Handle error event
    if event == "screenshot_error":
        error_msg = payload.get("message", "Unknown error")
        error_detail = payload.get("error", "No detailed information")
        logger.error(
            f"Error occurred during screenshot process: {error_msg}, Details: {error_detail}"
        )
        return [{"status": "error", "message": f"{error_msg}"}]

    # Handle screenshot save success event
    if event == "screenshot_saved":
        if not screenshot_called:
            logger.error("Screenshot function call not detected")
            return None

        if not screenshot_success:
            logger.error("Screenshot function execution failed")
            return None

        if not save_path:
            logger.error("Failed to get screenshot save path")
            return None

        # Verify screenshot path and size
        key_step.extend(verify_screenshot_path(save_path, logger, task_parameter))
        key_step.extend(verify_screenshot_size(save_path, logger, task_parameter))

        return key_step

    if event == "RequestHandlerSaveScreenshot_returned":
        # Check if there is a valid .png file in the save_path folder set in config.json
        config_save_path = task_parameter.get("save_path")
        if not config_save_path:
            logger.error("Save path not found in configuration")
            return [
                {"status": "error", "message": "Save path not found in configuration"}
            ]

        try:
            file_path = config_save_path
            if not os.path.exists(file_path):
                logger.error(f"File {file_path} does not exist")
                return [
                    {"status": "error", "message": f"File {file_path} does not exist"}
                ]

            with Image.open(file_path) as img:
                width, height = img.size
                expected_width = task_parameter["width"]
                expected_height = task_parameter["height"]

                if width != expected_width or height != expected_height:
                    logger.error(
                        f"Resolution of file {file_path} does not match: "
                        f"Expected {expected_width}x{expected_height}, Actual {width}x{height}"
                    )
                    return [
                        {
                            "status": "error",
                            "message": f"Resolution of file {file_path} does not match: Expected {expected_width}x{expected_height}, Actual {width}x{height}",
                        }
                    ]

            logger.info(f"File {file_path} verified successfully")
            return [
                {"status": "key_step", "index": 1},
                {"status": "key_step", "index": 2},
                {
                    "status": "success",
                    "message": f"File {file_path} verified successfully",
                },
            ]
        except Exception as e:
            logger.error(f"Error occurred while checking file: {e}")
            return [
                {
                    "status": "error",
                    "message": f"Error occurred while checking file: {e}",
                }
            ]

    return None
