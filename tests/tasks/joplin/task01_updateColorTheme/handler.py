#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin修改主题颜色的事件处理器
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
        changed_theme = message.get("data")
        expected_theme = task_parameter.get('theme', "Light")
        
        logger.info(f"正在检测主题颜色是否为: {expected_theme}")
        logger.info(f"当前Joplin主题颜色为: {changed_theme}")
        
        if changed_theme == expected_theme:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"颜色主题已经成功设置成{expected_theme}"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"主题颜色不匹配，期望：{expected_theme}，实际：{changed_theme}"}]
    return None 