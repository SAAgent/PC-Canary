#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin修改主题颜色的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    # 添加详细的日志记录
    logger.info("收到消息: %s", message)
    logger.info("任务参数: %s", task_parameter)
    
    event_type = message.get('event_type')
    logger.info("事件类型: %s", event_type)
    
    if event_type == "evaluate_on_completion":
        changed_theme = message.get("data")
        expected_theme = task_parameter.get('theme', "Light")
        logger.info("当前主题: %s, 期望主题: %s", changed_theme, expected_theme)
        
        if changed_theme == expected_theme:
            logger.info("主题匹配成功")
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"颜色主题已经成功设置成{expected_theme}"}
            ]
        else:
            logger.info("主题不匹配")
    return None 