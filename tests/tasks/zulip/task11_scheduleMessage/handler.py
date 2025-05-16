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
import re
import datetime

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    
    target_time = task_parameter.get("schedule_time", None)
    
    # convert target_time to unix time
    time_format = "%Y-%m-%d %H:%M:%S"
    dt = datetime.datetime.strptime(target_time, time_format)
    target_unix_schdule_time = int(dt.timestamp())

    target_message_info = task_parameter.get("message_info", None)
    target_channel_id = task_parameter.get("channel_id", None)

    scheduled_messages = message.get("scheduled_messages", [])

    if not scheduled_messages:
        print(f"scheduled_messages is empty")
        return [{"status": "error", "type": "evaluate_on_completion", "message": "没有找到定时消息,任务没有完成"}]

    # print("-" * 100)
    # print(f"{scheduled_messages}")

    # is_pin = any(
    #     message.get("scheduled_delivery_timestamp")==target_unix_schdule_time \
    #     for message in scheduled_messages
    # )

    # is_pin = any(
    #     str(message.get("to")) == target_channel_id \
    #     and message.get("content") == target_message_info \
    #     for message in scheduled_messages
    # )
    
    is_pin = any(
        str(message.get("to")) == target_channel_id and message.get("scheduled_delivery_timestamp")==target_unix_schdule_time \
        and message.get("content") == target_message_info \
        for message in scheduled_messages
    )

    if is_pin:
        return [
            {"status": "key_step", "index": 1},
            {"status": "success", "reason": f"成功设置scheduled_message, 目标频道: {target_channel_id}, 目标时间: {target_unix_schdule_time}, 目标消息: {target_message_info}"},
        ]
    else:
        return [{"status": "error", "type": "evaluate_on_completion", "message": "没有找到定时消息,任务没有完成"}]