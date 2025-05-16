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
    target_message = task_parameter.get("message", None)
    target_email = task_parameter.get("email", None)

    latest_message = message.get("content", None)
    latest_message = parse(latest_message)
    receiver_name = message.get('display_recipient', [])


    if latest_message == target_message \
        and any([i.get("email", None) == target_email for i in receiver_name]):
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功向{target_email}发送消息{target_message}"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
