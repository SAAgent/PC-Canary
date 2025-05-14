#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin移动笔记的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        notebook_list = data.get("notebooks", [])
        notebook_notes = data.get("notebook_notes", [])
        
        expected_note = task_parameter.get('note_name', "test_note")
        expected_notebook = task_parameter.get('target_notebook', "target_notebook")
        
        # 检查目标笔记本是否存在
        if expected_notebook not in notebook_list:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"目标笔记本 {expected_notebook} 不存在"}]
        
        # 获取指定笔记本下的所有笔记
        notebook_notes_in_target = [
            note for note in notebook_notes
            if note.get("note_title") == expected_note and note.get("parent_name") == expected_notebook
        ]
        
        # 检查笔记是否在目标笔记本下
        if notebook_notes_in_target:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功将笔记 {expected_note} 移动到了笔记本 {expected_notebook} 下"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"笔记 {expected_note} 不在笔记本 {expected_notebook} 下"}]
    return None 