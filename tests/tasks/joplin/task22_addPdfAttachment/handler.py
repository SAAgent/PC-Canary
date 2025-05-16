#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin添加PDF附件的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List
import os

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        notebook_list = data.get("notebooks", [])
        notebook_notes = data.get("notebook_notes", [])
        
        expected_notebook = task_parameter.get('notebook_name', "TestNotebook")
        expected_note_title = task_parameter.get('note_title', "TestNote")
        
        # 获取期望的PDF文件名 - 只获取基本文件名
        pdf_file_path = task_parameter.get('pdf_file_path', "")
        expected_pdf_filename = os.path.basename(pdf_file_path)
        logger.info(f"预期PDF文件名: {expected_pdf_filename}")
        
        # 检查笔记本是否存在
        if expected_notebook not in notebook_list:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"笔记本 {expected_notebook} 不存在"}]
        
        # 获取指定笔记本下的所有笔记
        notebook_notes_in_target = [
            note for note in notebook_notes
            if note.get("parent_name") == expected_notebook
        ]
        
        # 查找目标笔记
        target_note = None
        for note in notebook_notes_in_target:
            if note.get("note_title") == expected_note_title:
                target_note = note
                break
        
        if not target_note:
            return [{"status": "error", "type": "evaluate_on_completion", 
                    "message": f"在笔记本 {expected_notebook} 下没有找到标题为 {expected_note_title} 的笔记"}]
        
        # 检查笔记是否有PDF附件
        has_pdf = target_note.get("has_pdf", False)
        attachments = target_note.get("attachments", [])
        
        # 如果找到了PDF附件，返回成功结果
        if has_pdf:
            # 简化返回数据
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功将PDF文件添加到笔记本 {expected_notebook} 下的笔记 {expected_note_title} 中"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", 
                    "message": f"在笔记 {expected_note_title} 中没有找到PDF附件"}]
    return None 