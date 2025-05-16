#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, Callable, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:


    target_emoji = task_parameter.get("emoji", None)
    emoji = message.get("last_message", {}).get("reactions", [])[-1].get("emoji_name", None) if message.get("last_message", {}).get("reactions", [])!=[] else None
    
    # compare message_id
    if not message.get("message_id", None) == message.get("last_message", {}).get("id", None):
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    
    # compare sender_id
    if not message.get("self_id", None) == message.get("last_message", {}).get("sender_id", None):
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    
    # compare emoji
    if not emoji == target_emoji or emoji == None:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]

    return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功向最新的消息中添加{target_emoji} emoji"}
    ]
