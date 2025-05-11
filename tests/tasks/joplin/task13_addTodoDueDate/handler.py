#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin添加待办事项截止日期的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List

def load_config_defaults() -> Dict[str, Any]:
    """从config.json加载默认参数值"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config.get('task_parameters', {})

def timestamp_to_date(timestamp: int) -> str:
    """将时间戳转换为YYYY-MM-DD格式的日期字符串"""
    try:
        # 将毫秒时间戳转换为秒
        seconds = timestamp / 1000
        # 转换为datetime对象
        dt = datetime.fromtimestamp(seconds)
        # 格式化为YYYY-MM-DD
        return dt.strftime('%Y-%m-%d')
    except (ValueError, TypeError):
        return ''

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        todos = data.get("todos", [])
        
        # 从config.json加载默认值
        config_defaults = load_config_defaults()
        expected_todo = task_parameter.get('todo_name', config_defaults.get('todo_name'))
        expected_date = task_parameter.get('due_date', config_defaults.get('due_date'))
        
        # 查找指定名称的待办事项
        target_todo = next((todo for todo in todos if todo.get("title") == expected_todo), None)
        
        if not target_todo:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"名为 {expected_todo} 的待办事项不存在"}]
        
        # 检查待办事项是否设置了截止日期
        todo_due_timestamp = target_todo.get("todo_due", "")
        todo_due_date = timestamp_to_date(todo_due_timestamp) if todo_due_timestamp else ""
        
        logger.info(f"待办事项 {expected_todo} 的截止日期时间戳: {todo_due_timestamp}")
        logger.info(f"转换后的日期: {todo_due_date}")
        logger.info(f"期望的日期: {expected_date}")
        
        if todo_due_date == expected_date:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功为待办事项 {expected_todo} 设置截止日期：{expected_date}"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"待办事项 {expected_todo} 的截止日期不匹配，期望：{expected_date}，实际：{todo_due_date}"}]
    return None 