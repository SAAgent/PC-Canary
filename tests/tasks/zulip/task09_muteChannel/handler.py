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

    subscriptions = message.get("subscriptions",[])
    target_channel = task_parameter.get("channel_name", "feedback")

    assert subscriptions is not []

    is_pin = any(
        s.get("name") == target_channel and s.get("is_muted", None) == True \
        for s in subscriptions
    )

    if is_pin == True:
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功将用{target_channel}Channel固定到顶部"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]