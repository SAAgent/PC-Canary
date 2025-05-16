#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin检查待办事项是否被删除的事件处理器
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
        
        # 查找指定内容的待办事项
        target_todo = next((todo for todo in todo_list if todo['title'] == expected_content), None)
        
        # 如果找不到待办事项，说明已经被删除
        if target_todo is None:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"待办事项 {expected_content} 已被成功删除"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"待办事项 {expected_content} 仍然存在，未被删除"}]
    return None 