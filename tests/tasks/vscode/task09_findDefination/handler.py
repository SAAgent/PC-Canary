#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    expected_line_begin = task_parameter.get("expected_line_begin", 241)
    expected_line_end = task_parameter.get("expected_line_end", 248)
    expected_file_name = task_parameter.get("expected_file", '/root/C-Plus-Plus/ciphers/uint256_t.hpp')
    if event_type == "evaluate_on_completion":
        breakpoints_info = message.get('breakpoints')
        if any([i['file'] == expected_file_name and i['line'] >= expected_line_begin and i['line'] <= expected_line_end for i in breakpoints_info]):
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    elif event_type == "open_file":
        file_path = message.get("path")
        if message.get("scheme") == "git":
            file_path = file_path[:-4]
        if file_path == expected_file_name:
            return [{"status": "key_step", "index": 1}]
    return None
