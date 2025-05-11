#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin修改笔记标题的事件处理器
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
        old_note_name = task_parameter.get('old_note_name', "hi")
        new_note_name = task_parameter.get('new_note_name', "hello world")
        
        # 检查笔记本是否存在
        if expected_notebook not in notebook_list:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"笔记本 {expected_notebook} 不存在"}]
        
        # 获取指定笔记本下的所有笔记
        notebook_notes_in_target = [
            note for note in notebook_notes
            if note["parent_name"] == expected_notebook
        ]
        
        # 检查笔记是否已修改为新的标题
        found_new_title = False
        found_old_title = False
        
        for note in notebook_notes_in_target:
            if note["note_title"] == new_note_name:
                found_new_title = True
            if note["note_title"] == old_note_name:
                found_old_title = True
        
        if found_new_title and not found_old_title:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功将笔记本 {expected_notebook} 下的笔记 {old_note_name} 的标题修改为 {new_note_name}"}
            ]
        elif found_old_title:
            return [{"status": "error", "type": "evaluate_on_completion", 
                    "message": f"笔记标题未成功修改，原标题 {old_note_name} 仍然存在"}]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", 
                    "message": f"在笔记本 {expected_notebook} 下没有找到标题为 {new_note_name} 的笔记"}]
    return None 