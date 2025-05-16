#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin笔记排序方式检查事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        sort_field = data.get("sort_field")
        sort_order = data.get("sort_order")
        
        expected_field = task_parameter.get('sort_field', 'title')
        expected_order = task_parameter.get('sort_order', 'desc')
        
        logger.info(f"期望排序字段: {expected_field}, 期望排序方式: {expected_order}")
        logger.info(f"实际排序字段: {sort_field}, 实际排序方式: {sort_order}")
        
        if sort_field == expected_field and sort_order == expected_order:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"当前排序方式为：{sort_field} {sort_order}"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", 
                    "message": f"排序方式不匹配，期望：{expected_field} {expected_order}，实际：{sort_field} {sort_order}"}]
    return None 