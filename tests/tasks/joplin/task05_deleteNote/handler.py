#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin删除笔记的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        current_notes = data.get("notes", [])
        
        expected_note = task_parameter.get('note_name', "test_note")
        
        # 检查笔记是否已被删除（即不在当前笔记列表中）
        if expected_note not in current_notes:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功删除了名为 {expected_note} 的笔记"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"名为 {expected_note} 的笔记仍然存在"}]
    return None 