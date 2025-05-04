#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
vscode修改主题颜色的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    if event_type == "evaluate_on_completion":
        changed_theme = message.get("data")
        expected_theme = task_parameter.get('theme', "Default Light+")
        if changed_theme == expected_theme:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"颜色主题已经成功设置成{expected_theme}"}
            ]
    return None
