#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin创建待办事项的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        todo_list = data.get("todos", [])
        
        expected_content = task_parameter.get('todo_content', "test_todo")
        
        # 检查是否存在指定内容的待办事项
        if expected_content in todo_list:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功创建了内容为 {expected_content} 的待办事项"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"未找到内容为 {expected_content} 的待办事项"}]
    return None 