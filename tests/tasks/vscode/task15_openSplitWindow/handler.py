#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message)
    expected_first = task_parameter.get("first_file", "bubble_sort.cpp")
    expected_second = task_parameter.get("second_file", "bead_sort.cpp")
    expected_first_path = task_parameter.get("expected_first_path", "/root/C-Plus-Plus/sorting/bubble_sort.cpp")
    expected_second_path = task_parameter.get("expected_second_path", "/root/C-Plus-Plus/sorting/bead_sort.cpp")
    if event_type == "evaluate_on_completion":
        split_info = message.get('info', {}).get('splitInfo', None)
        if not split_info or len(split_info) != 2:
            return None
        files = []
        for i in split_info:
            group = i.get('tabs', None)
            if not group:
                return None
            files.append([j.get('label', None) for j in group if j.get('isActive', False)])
        if (expected_first in files[0] and expected_second in files[1]) or (expected_first in files[1] and expected_second in files[0]):
            return [
                {"status": "key_step", "index": 3},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    elif event_type == "open_file":
        file_path = message.get("path")
        if message.get("scheme") == "git":
            file_path = file_path[:-4]
        if file_path == expected_first_path:
            return [{"status": "key_step", "index": 1}]
        elif file_path == expected_second_path:
            return [{"status": "key_step", "index": 2}]
    return None
