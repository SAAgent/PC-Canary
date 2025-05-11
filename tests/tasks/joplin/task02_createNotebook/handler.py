#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin检查笔记本是否存在的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        notebook_list = message.get("data", [])
        expected_notebook = task_parameter.get('notebook_name', "测试笔记本")
        
        if expected_notebook in notebook_list:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功找到名为 {expected_notebook} 的笔记本"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None 