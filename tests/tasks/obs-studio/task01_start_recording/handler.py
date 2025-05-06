#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message.get('payload')
    event_type = payload.get('event')
    logger.info(payload.get('message', ''))

    if event_type == "is_recording_active":
        recording = payload.get("recording", False)
        logger.info(f"obs-studio的录制状态是 {recording}")
        
        if recording:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "已经开始录制"},
            ]

    return None