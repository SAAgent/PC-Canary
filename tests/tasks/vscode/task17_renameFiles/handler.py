#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from typing import Dict, Any, Optional, List

ORIGIN_FILE_LIST = None

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    global ORIGIN_FILE_LIST
    event_type = message.get('event_type')
    logger.info(message)
    expected_relative_path = task_parameter.get("relative_path", "greedy_algorithms")
    expected_origin_suffix = task_parameter.get("origin_suffix", ".h")
    expected_suffix = task_parameter.get("expected_suffix", ".hpp")
    if event_type == "get_root_when_start":
        root = message.get('root', '')
        dir_path = os.path.join(root, expected_relative_path)
        ORIGIN_FILE_LIST = os.listdir(dir_path)
    elif event_type == "evaluate_on_completion" and ORIGIN_FILE_LIST is not None:
        root = message.get('root', '')
        dir_path = os.path.join(root, expected_relative_path)
        file_list = os.listdir(dir_path)
        expected_file_list = [i if not i.endswith(expected_origin_suffix) else i.replace(expected_origin_suffix, expected_suffix) for i in ORIGIN_FILE_LIST]
        file_list.sort()
        expected_file_list.sort()
        logger.info(expected_file_list)
        logger.info(file_list)
        if file_list == expected_file_list:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None
