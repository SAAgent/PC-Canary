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
    def parse(content: str) -> str:
        """
        解析消息内容
        """
        if content.startswith("<p>") and content.endswith("</p>"):
            return content[3:-4]
        return content

    print("-" * 100)
    print(f"{message}")


    target_channel = task_parameter.get("target_channel", None)
    target_topic = task_parameter.get("target_topic", None)
    
    target_message = message.get("target_message",None)
    channel = message.get("last_message",None).get("display_recipient", None)
    topic = message.get("last_message",None).get("subject", None)
    content = message.get("last_message",None).get("content", None)
    content = parse(content)
    
    if channel != target_channel:
        print(f"Channel不匹配: {channel} != {target_channel}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    
    if topic != target_topic:
        print(f"Topic不匹配: {topic} != {target_topic}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    
    if content != target_message:
        print(f"Message不匹配: {content} != {target_message}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]

    return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功向{target_channel} Channel中的{target_topic} topic发送消息{target_message}"}
        ]

