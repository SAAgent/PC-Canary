#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
from typing import Dict, Any, Optional, List

step = 0

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global step
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    if event_type == "hotkey_press":
        name = payload.get("name", "")
        if name == "OBSBasic.StartRecording":
            if step == 2:
                return [
                    {"status": "key_step", "index": 3},
                    {"status": "success", "reason": "成功找到热键并且触发测试完成"},
                ]
            
    elif event_type == "inject_hotkey":
        name = payload.get("name", "")
        if name == "OBSBasic.StartRecording":
            if step == 2:
                return [
                    {"status": "key_step", "index": 3},
                    {"status": "success", "reason": "成功找到热键并且触发测试完成"},
                ]

    elif event_type == "set_hotkey_success":
        name = payload.get("name", "")
        print("set_hotkey_success: " + name)
        if name == "OBSBasic.StartRecording" or name == "OBSBasic.StopRecording":
            if step == 0 :
                step = 1
                return [
                    {"status": "key_step", "index": 1},
                ]

    elif event_type == "save_success":
        file_path = payload.get("file", "")
        if not file_path:
            logger.error("未获取到配置文件路径")
            return None
        logger.info(f"配置文件路径: {file_path}")

        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(file_path)
            
            if not config.has_section("Hotkeys"):
                return [
                    {"status": "error", "reason": "script_error", "message": "配置文件中未找到热键配置"},
                ]
                
            start_recording = config.get("Hotkeys", "OBSBasic.StartRecording", fallback="")
            stop_recording = config.get("Hotkeys", "OBSBasic.StopRecording", fallback="")
            
            if not start_recording or not stop_recording:
                return [
                    {"status": "error", "reason": "script_error", "message": "未找到录制相关的热键配置"},
                ]
                
            import json
            start_bindings = json.loads(start_recording).get("bindings", [])
            stop_bindings = json.loads(stop_recording).get("bindings", [])
            
            if not start_bindings or not stop_bindings:
                return [
                    {"status": "error", "reason": "script_error", "message": "录制热键未设置绑定"},
                ]
                
            start_key = start_bindings[0]
            stop_key = stop_bindings[0]
            expected_key = task_parameter.get("hotkey", {})
            
            if start_key == expected_key and stop_key == expected_key:
                if step == 1:
                    step = 2
                    return [
                        {"status": "key_step", "index": 2}
                    ]
            else:
                return [
                    {"status": "error", "reason": "script_error", "message": "热键配置不正确"},
                ]
                
        except Exception as e:
            return [
                {"status": "error", "reason": "script_error", "message": f"验证热键配置时出错: {str(e)}"},
            ]

    return None
