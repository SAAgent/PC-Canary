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
    print(f"message:{message}")

    # latest_message = message.get("content", None)
    # receiver_name = message.get('display_recipient', [])
    
    channel = message.get("display_recipient", None)
    topic = message.get("subject", None)
    content = message.get("content", None)
    content = parse(content)

    target_message = task_parameter.get("message", None)
    target_channel = task_parameter.get("channel_name", None)
    target_topic = task_parameter.get("topic_name",None)
    

    if content == target_message and topic == target_topic and channel == target_channel:
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功向{target_channel} Channel中的{target_topic}话题发送消息{target_message}"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
