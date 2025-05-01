#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, Callable, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message)
    if event_type == "get_work_spaces":
        work_spaces = message.get('work_spaces')
        expected_work_space = task_parameter.get("work_space_dir", "/root/C-Plus-Plus/data_structures")
        if len(work_spaces) == 1 and expected_work_space == work_spaces[0]:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"任务成功完成"}
            ]
    elif event_type == "evaluate_on_completion":
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None
