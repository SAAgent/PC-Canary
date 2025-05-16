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

    expected_status = task_parameter.get("user_status", "Vacationing")
    cur_status = message.get("status",None)
    statsus_text = cur_status.get("status_text",None)
    if statsus_text == expected_status:
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功将用户状态设置为{expected_status}"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]