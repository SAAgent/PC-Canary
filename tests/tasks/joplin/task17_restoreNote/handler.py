#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin恢复笔记的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        current_notes = data.get("notes", [])
        deleted_notes = data.get("deleted_notes", [])
        
        expected_note = task_parameter.get('note_name', "test_note")
        
        # 检查笔记是否已从回收站恢复（即在当前笔记列表中，且不在已删除笔记列表中）
        if expected_note in current_notes and expected_note not in deleted_notes:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功从回收站恢复了名为 {expected_note} 的笔记"}
            ]
        elif expected_note in deleted_notes:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"名为 {expected_note} 的笔记仍在回收站中"}]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"名为 {expected_note} 的笔记不存在"}]
    return None 