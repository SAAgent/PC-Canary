#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message)
    expected_file1 = task_parameter.get("file1", "/root/C-Plus-Plus/sorting/quick_sort.cpp")
    expected_file2 = task_parameter.get("file2", "/root/C-Plus-Plus/sorting/quick_sort_3.cpp")
    if event_type == "evaluate_on_completion":
        info = message.get('info', None)
        if not info:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
        files = [info.get('originalPath', None), info.get('modifiedPath', None)]
        if expected_file1 in files and expected_file2 in files:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None
