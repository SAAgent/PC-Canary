#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin添加笔记内容的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import json
import os
from typing import Dict, Any, Optional, List

def load_config_defaults() -> Dict[str, Any]:
    """从config.json加载默认参数值"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config.get('task_parameters', {})

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        notes = data.get("notes", [])
        
        # 从config.json加载默认值
        config_defaults = load_config_defaults()
        expected_note = task_parameter.get('note_name', config_defaults.get('note_name'))
        expected_text = task_parameter.get('append_text', config_defaults.get('append_text'))
        
        # 查找指定名称的笔记
        target_note = next((note for note in notes if note.get("title") == expected_note), None)
        
        if not target_note:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"名为 {expected_note} 的笔记不存在"}]
        
        # 检查笔记内容是否包含指定文字
        note_body = target_note.get("body", "")
        if expected_text in note_body:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功在笔记 {expected_note} 中添加了文字：{expected_text}"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"笔记 {expected_note} 中未找到指定文字：{expected_text}"}]
    return None 