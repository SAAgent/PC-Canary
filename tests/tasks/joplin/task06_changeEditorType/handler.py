#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin修改编辑器类型的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    # 打印完整的参数信息
    logger.info("="*50)
    logger.info("参数调试信息:")
    logger.info(f"task_parameter 类型: {type(task_parameter)}")
    logger.info(f"task_parameter 内容: {task_parameter}")
    logger.info("="*50)
    
    if event_type == "evaluate_on_completion":
        current_editor_type = message.get("data")
        expected_editor_type = task_parameter.get('editor_type', "richtext")
        
        logger.info(f"正在检测编辑器类型是否为: {expected_editor_type}")
        logger.info(f"当前Joplin编辑器类型为: {current_editor_type}")
        
        if current_editor_type == expected_editor_type:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"编辑器类型已经成功设置为{expected_editor_type}"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"编辑器类型不匹配，期望：{expected_editor_type}，实际：{current_editor_type}"}]
    return None