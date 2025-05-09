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
    latest_message = message.get("content", None)
    receiver_name = message.get('display_recipient', [])
    expected_content = task_parameter.get("expected_content", "<p>Nice to meet you!</p>")
    expected_full_name = task_parameter.get("user_name", "David")
    if latest_message == expected_content\
        and any([i.get("full_name", None) == expected_full_name for i in receiver_name]):
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功向{expected_full_name}发送消息{expected_content}"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
