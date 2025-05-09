#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OBS Studio 添加 Stinger 过渡并演示切换
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, List

# 任务成功条件的追踪状态
_STINGER_CREATED = False
_STINGER_CONFIGURED = False
_STINGER_USED = False

key_steps = []

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global key_steps
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    global _EVALUATOR, _CONFIG, _START_TIME, _STINGER_CREATED, _STINGER_CONFIGURED, _STINGER_USED
                
    if event_type == "stinger_transition_created":
        logger.info("Stinger过渡已创建")
        _STINGER_CREATED = True
        if not dict_have_index(key_steps, 1):
            key_steps.append({"status": "key_step", "index": 1})

    # Stinger过渡配置相关事件
    elif event_type == "configureStingerTransition_called":
        logger.info("拦截到配置Stinger过渡函数调用")
        
    elif event_type == "configureStingerTransition_returned":
        logger.info("配置Stinger过渡函数返回")
        expected_file = task_parameter.get("stinger_file", "")
        expected_transition_point = task_parameter.get("transition_point_ms", 0)
        file = payload.get("file")
        try:
            with open(file, "r") as f:
                data = json.load(f)
                transitions = data.get("transitions", [])
                for transition in transitions:
                    if transition.get("id") == "obs_stinger_transition":
                        transition_point = transition.get("settings", {}).get("transition_point", 0)
                        transition_file = transition.get("settings", {}).get("path", "")

                        if transition_point == expected_transition_point and transition_file == expected_file:
                            logger.info("Stinger过渡配置文件验证成功: transition_point为300")
                            _STINGER_CONFIGURED = True
                            if not dict_have_index(key_steps, 2):
                                key_steps.append({"status": "key_step", "index": 2})
                        else:
                            logger.warning(f"Stinger过渡配置文件验证失败: transition_point为{transition_point}, 期望值为300")
        except Exception as e:
            logger.error(f"读取或解析配置文件失败: {str(e)}")

    elif event_type == "stinger_transition_used":
        logger.info("Stinger过渡已使用")
        _STINGER_USED = True
        if not dict_have_index(key_steps, 3):
            key_steps.append({"status": "key_step", "index": 3})

    # 检查任务是否完成
    if _STINGER_CREATED and _STINGER_CONFIGURED and _STINGER_USED:
        key_steps.append({"status": "success", "reason": "所有设置已成功完成"})
        return key_steps
    
    return None

def dict_have_index(key_steps: List[Dict[str, Any]], index: int) -> bool:
    for key_step in key_steps:
        if "index" in key_step and key_step["index"] == index:
            return True
    
    return False