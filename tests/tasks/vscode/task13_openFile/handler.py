#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    expected_file_path = task_parameter.get("expected_file_path", "/root/C-Plus-Plus/sorting/recursive_bubble_sort.cpp")
    if event_type == "evaluate_on_completion":
        file_name = message.get('info', {}).get('fileName', None)
        line_number = message.get('info', {}).get('lineNumber', None)
        expected_filename = task_parameter.get("filename", "recursive_bubble_sort.cpp")
        expected_line = task_parameter.get("expected_line", 84)
        if file_name == expected_filename and line_number == expected_line:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    elif event_type == "open_file":
        file_path = message.get("path")
        if message.get("scheme") == "git":
            file_path = file_path[:-4]
        if file_path == expected_file_path:
            return [{"status": "key_step", "index": 1}]
    return None
