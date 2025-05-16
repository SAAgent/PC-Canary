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

    expected_online_status = task_parameter.get("online_status","offline")

    presence = message.get("presence",None)
    online_status = presence.get("aggregated",None).get("status",None)

    print("-" * 100)
    print(f"online_status:{online_status}")
    if expected_online_status == online_status:
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功将用户在线状态设置为{expected_online_status}"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
        