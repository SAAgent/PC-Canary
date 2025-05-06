#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
obs切换转场动画操作
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    if event_type == "current_transition":
        logger.info("获得当前转场动画模式")     
        expected_transition = task_parameter.get("transition", "")
        transition = payload.get('transition', '')
        print(f"expected_scene: {expected_transition}, transition: {transition}")
        if expected_transition == transition:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "成功切换转场动画"},
            ]
        
    return None