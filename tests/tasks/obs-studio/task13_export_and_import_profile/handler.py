#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    if event_type == "export_success":
        export_path = task_parameter.get("export_path", "")
        profile_name = task_parameter.get("profile_name", "")
        expected_path = os.path.join(export_path, profile_name)
        if os.path.exists(expected_path):
            return [
                {"status": "key_step", "index": 1},
            ]
        else:
            return [
                {"status": "error", "reason": "script_error", "message": "找不到对应配置文件"},
            ]
            
    elif event_type == "import_success":
        import_path = task_parameter.get("import_path", "")
        have_dir = os.path.exists(import_path)
        success = (True if payload.get("import_success", "") == "True" else False) and have_dir
        if success:
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": "成功导入配置文件"},
            ]
    return None
