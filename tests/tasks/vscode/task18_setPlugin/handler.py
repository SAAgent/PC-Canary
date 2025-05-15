#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message)
    expected_value = task_parameter.get("info", False)
    expected_name = task_parameter.get("plugin_name", "TODO Highlight")
    if event_type == "evaluate_on_completion":
        if expected_value == message.get('info', None) and expected_name in message.get('names', []):
            return [
                {"status": "key_step", "index": 1},
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        elif expected_name in message.get('names', []):
            return [
                {"status": "key_step", "index": 1},
                {"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}
            ]
        else:
            return [
                {"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}
            ]
    return None
