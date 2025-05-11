#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin检查当前笔记的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        current_note = message.get("data")
        expected_note = task_parameter.get('note_name', "测试笔记")
        
        if current_note is None:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "当前没有打开的笔记"}]
        
        if current_note == expected_note:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功找到名为 {expected_note} 的笔记"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"当前打开的笔记不是 {expected_note}，而是 {current_note}"}]
    return None 