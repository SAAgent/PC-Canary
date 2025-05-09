#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, Callable, Set, List

_DELETED_SOURCES = set()  # 用于跟踪已删除的源

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    # 处理源删除事件
    if event_type == "source_deleted":
        source_name = payload.get("source_name")
        if source_name in task_parameter["source_names"]:
            _DELETED_SOURCES.add(source_name)
            logger.info(f"源 {source_name} 已删除")
            
            # 检查是否所有需要的源都已删除
            if _DELETED_SOURCES == set(task_parameter["source_names"]):
                return [
                    {"status": "key_step", "index": 1},
                    {"status": "success", "reason": "删除色源成功"},
                ]

    return None
