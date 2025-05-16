#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin给多个笔记添加标签的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import json
import os
import sys
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
        expected_notes = task_parameter.get('note_names', config_defaults.get('note_names', []))
        expected_tag = task_parameter.get('tag_name', config_defaults.get('tag_name'))
        
        # 检查每个笔记是否都存在
        missing_notes = []
        notes_without_tag = []
        
        for note_name in expected_notes:
            target_note = next((note for note in notes if note.get("title") == note_name), None)
            if not target_note:
                missing_notes.append(note_name)
            elif expected_tag not in target_note.get("tags", []):
                notes_without_tag.append(note_name)
        
        if missing_notes:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"以下笔记不存在：{', '.join(missing_notes)}"}]
        
        if notes_without_tag:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"以下笔记未添加标签 {expected_tag}：{', '.join(notes_without_tag)}"}]
        
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功给所有笔记添加了标签：{expected_tag}"}
        ]
    return None

if __name__ == '__main__':
    # 从标准输入读取评估数据
    input_data = sys.stdin.read()
    data = json.loads(input_data)
    
    # 评估结果
    result = message_handler(data, sys.stderr, load_config_defaults())
    
    # 输出评估结果
    if result:
        print(json.dumps(result, ensure_ascii=False)) 