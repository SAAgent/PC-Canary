#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, Callable, List

file_path = None
origin_file_content = None

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    global origin_file_content, file_path
    event_type = message.get('event_type')
    logger.info(message)
    expected_path = task_parameter.get("expected_path", "/root/C-Plus-Plus/sorting/bubble_sort.cpp")
    if event_type == "open_file":
        file_path = message.get("path")
        if message.get("scheme") == "git":
            file_path = file_path[:-4]
        if file_path == expected_path:
            return [
                {"status": "key_step", "index": 1}
            ]
    elif event_type == "read_origin_content":
        origin_file_content = message.get("content")
    elif event_type == "evaluate_on_completion":
        if origin_file_content:
            with open(expected_path, "r", encoding="UTF8") as f:
                changed_file_content = f.read()
            origin_name = task_parameter.get("origin_name", "swap_check")
            expected_name = task_parameter.get("expected_name", "swap_flag")
            expected_content = "".join(origin_file_content.replace(origin_name, expected_name).split())
            now_content = "".join(changed_file_content.split())
            logger.info(f"{expected_content}")
            logger.info(f"{now_content}")
            if expected_content == now_content:
                return [
                    {"status": "key_step", "index": 2},
                    {"status": "success", "reason": f"文件成功修改"}
                ]
            else:
                return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None
