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
     
    # def parse(content: str) -> str:
    #     """
    #     解析消息内容
    #     """
    #     if content.startswith("<p>") and content.endswith("</p>"):
    #         return content[3:-4]
    #     return content

    source_message_content = message.get("source_message", None).get("content", None)
    target_message_content = message.get("target_message", None).get("content", None)

    if source_message_content != target_message_content:
        print(f"源消息不匹配, 源消息: {source_message_content}, 当前消息: {target_message_content}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]

    target_channel = task_parameter.get("target_channel", None)
    target_topic = task_parameter.get("target_topic", None)
    
    channel = message.get("target_message",None).get("display_recipient", None)
    topic = message.get("target_message",None).get("subject", None)

    if target_channel != channel:
        print(f"目标频道不匹配, 目标频道: {target_channel}, 当前频道: {channel}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": f"目标频道不匹配, 目标频道: {target_channel}, 当前频道: {channel}"}]

    if target_topic != topic:
        print(f"目标主题不匹配, 目标主题: {target_topic}, 当前主题: {topic}")
        return [{"status": "error", "type": "evaluate_on_completion", "message": f"目标主题不匹配, 目标主题: {target_topic}, 当前主题: {topic}"}]


    return [
        {"status": "key_step", "index": 1},
        {"status": "success", "reason": f"成功向{target_channel} Channel中的{target_topic} topic发送消息"}
    ]

