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
    expected_channel_name = task_parameter.get("channel_name", "feedback")
    expected_topic_name = task_parameter.get("topic_name", "Incomplete documentation")
    expected_content = task_parameter.get("expected_content", "<p>The introduction to various scripts is not comprehensive.</p>")
    if message.get("content", None) == expected_content\
        and message.get("display_recipient", None) == expected_channel_name\
        and message.get("subject", None) == expected_topic_name:
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功创建名为{expected_topic_name}的话题"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
