# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

"""
事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, Callable, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:


    def parse(content: str) -> str:
        """
        解析消息内容
        """
        if content.startswith("<p>") and content.endswith("</p>"):
            return content[3:-4]
        return content
    
    target_channel = task_parameter.get("target_channel", None)
    target_topic = task_parameter.get("target_topic", None)
    target_emoji = task_parameter.get("target_emoji", None)
    target_message = task_parameter.get("target_message", None)
    
    last_message = message.get("last_message", None)

    channel  = last_message.get("display_recipient", None)
    topic = last_message.get("subject", None)
    emoji = last_message.get("reactions", [])[-1].get("emoji_name", None) if message.get("reactions", []) != [] else None
    send_message = last_message.get("content", None)
    # send_message = parse(message.get("content", None))
    
    if target_channel != channel:
        print(f"target_channel: {target_channel}, channel: {channel}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": f"target_channel: {target_channel}, channel: {channel}"}]
    
    if target_topic != topic:
        print(f"target_topic: {target_topic}, topic: {topic}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": f"target_topic: {target_topic}, topic: {topic}"}]
    
    if target_message != send_message:
        print(f"target_message: {target_message}, send_message: {send_message}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": f"target_message: {target_message}, send_message: {send_message}"}]

    if target_emoji != emoji:
        print(f"target_emoji: {target_emoji}, emoji: {emoji}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": f"target_emoji: {target_emoji}, emoji: {emoji}"}]

    return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功向最新的消息中添加{target_emoji} emoji"}
    ]