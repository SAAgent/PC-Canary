#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, Callable, List

origin_file_content = None

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    global origin_file_content
    event_type = message.get('event_type')
    expected_file_name = task_parameter.get("expected_file_path", "/root/C-Plus-Plus/.vscode/settings.json")
    logger.info(message)
    if event_type == "read_origin_content":
        origin_file_content = message.get('data')
    elif event_type == "evaluate_on_completion":
        file_content = message.get('data')
        expected_font_size = task_parameter.get("font_size", 16)
        if "editor.fontSize" in file_content:
            font_size = file_content.pop("editor.fontSize")
            if "editor.fontSize" in origin_file_content:
                origin_file_content.pop("editor.fontSize")
            if font_size == expected_font_size and file_content == origin_file_content:
                return [
                    {"status": "key_step", "index": 2},
                    {"status": "success", "reason": f"成功配置文件"}
                ]
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    elif event_type == "open_file":
        file_path = message.get("path")
        if message.get("scheme") == "git":
            file_path = file_path[:-4]
        if file_path == expected_file_name:
            return [{"status": "key_step", "index": 1}]
    return None
