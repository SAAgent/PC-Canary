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
    streams = message.get("streams", None)
    members = message.get("members", None)
    # _EVALUATOR.logger.info(f"{streams}")
    # _EVALUATOR.logger.info(f"{members}")
    expected_name = task_parameter.get("channel_name", "bug report")
    expected_description = task_parameter.get("description", "welcome to report bugs")
    if any([i.get("name", None) == expected_name\
        and i.get("description", None) == expected_description\
        and i.get("count") == members for i in streams]):
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功创建名为{expected_name}的频道"}
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
