#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, Callable, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message)
    expected_file_name = task_parameter.get("expected_file_path", "/root/C-Plus-Plus/search/binary_search.cpp")
    if event_type == "evaluate_on_completion":
        is_file_opend = message.get("isFileOpen")
        file_name = message.get("fileName")
        are_block_folded = message.get("areBlockFolded")
        if is_file_opend and file_name == expected_file_name and are_block_folded:
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": f"文件成功打开并且代码块全部折叠"}
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
