#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin创建笔记的事件处理器
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
        
        expected_notebook = task_parameter.get('notebook_name', "hello")
        expected_note = task_parameter.get('note_name', "hi")
        
        # 检查笔记本是否存在
        if expected_notebook not in notebook_list:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"笔记本 {expected_notebook} 不存在"}]
        
        # 获取指定笔记本下的所有笔记
        notebook_notes_in_target = [
            note for note in notebook_notes
            if note["note_title"] == expected_note and note["parent_name"] == expected_notebook
        ]
        
        # 检查笔记是否在指定笔记本下
        if notebook_notes_in_target:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功在笔记本 {expected_notebook} 下创建了名为 {expected_note} 的笔记"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"在笔记本 {expected_notebook} 下没有找到名为 {expected_note} 的笔记"}]
    return None