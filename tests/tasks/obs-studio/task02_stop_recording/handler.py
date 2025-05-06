#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    if event_type == "obs_output_force_stop_returned" or event_type == "obs_output_stop_returned":                
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": "成功停止录制"},
        ]

    return None