#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
obs切换场景操作
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    
    if event_type == "current_scene":
        logger.info("获得当前场景场景名字")
        expected_scene = task_parameter.get("scene", "")
        scene = payload.get("scene", "")
        print(f"expected_scene: {expected_scene}, scene: {scene}")
        if expected_scene == scene:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "成功切换场景"},
            ]
    
    return None
