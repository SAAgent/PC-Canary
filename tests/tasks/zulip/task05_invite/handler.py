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
    roles = {
        "owner": 100,
        "administrator": 200,
        "moderator": 300,
        "member": 400,
        "guest": 600
    }
    invites = message.get("invites", [])
    expected_email = task_parameter.get("email", "xxxyyy@example.com")
    expected_role = roles[task_parameter.get("role", "guest")]
    if any([i.get('email', None) == expected_email and i.get('invited_as', None) == expected_role and i.get("expiry_date", 1) == None for i in invites]):
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功向{expected_email}发送邀请信息"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
