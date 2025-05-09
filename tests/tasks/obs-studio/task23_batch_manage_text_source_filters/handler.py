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

# 追踪滤镜相关状态
_FILTERS_ADDED = set()
_FILTERS_ENABLED = set()
_FILTERS_DISABLED = set()
_FILTERS_REMOVED = set()

filters_added = False
filters_enabled_disabled = False
filters_removed = False

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global filters_added, filters_enabled_disabled, filters_removed
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: injector消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _FILTERS_ADDED, _FILTERS_ENABLED, _FILTERS_DISABLED, _FILTERS_REMOVED
    
    # 获取期望的滤镜信息
    expected_filters = []
    filter_types_map = {}  # 用于存储滤镜名称和类型的映射
    
    expected_filters = [filter_info["name"] for filter_info in task_parameter["filters"]]
    
    # 创建滤镜名称到滤镜类型的映射
    for filter_info in task_parameter["filters"]:
        filter_types_map[filter_info["name"]] = filter_info["type"]
    
    # 处理从hooker.js发送过来的事件
    payload = message.get("payload", {})
    event_type = payload.get("event")
    
    logger.info(f"接收到事件: {event_type}, 负载: {payload}")
    
    if event_type == "filter_created":
        filter_name = payload.get("filterName")
        source_name = payload.get("sourceName")
        filter_kind = payload.get("filterKind")
        
        if filter_name in expected_filters:
            # 检查滤镜类型是否匹配
            expected_type = filter_types_map.get(filter_name)
            
            if expected_type and filter_kind:
                if expected_type in filter_kind or filter_kind in expected_type:
                    logger.info(f"滤镜 '{filter_name}' 类型匹配成功: 期望 '{expected_type}', 实际 '{filter_kind}'")
                    _FILTERS_ADDED.add(filter_name)
                    logger.info(f"滤镜 '{filter_name}' 已添加到源 '{source_name}'")
                else:
                    logger.warning(f"滤镜 '{filter_name}' 类型不匹配: 期望 '{expected_type}', 实际 '{filter_kind}'")
            else:
                # 如果没有类型信息，则仅基于名称检查
                _FILTERS_ADDED.add(filter_name)
                logger.info(f"滤镜 '{filter_name}' 已添加到源 '{source_name}'，但未进行类型检查")
            
            # 检查是否所有滤镜都已添加
            if all(filter_name in _FILTERS_ADDED for filter_name in expected_filters):
                logger.info("所有滤镜已成功添加")
                filters_added = True
                return [
                    {"status":"key_step", "index": 1}
                ]
    
    elif event_type == "filter_enabled":
        filter_name = payload.get("filterName")
        if filter_name in expected_filters:
            _FILTERS_ENABLED.add(filter_name)
            logger.info(f"滤镜 '{filter_name}' 已启用")
            
            # 检查启用和禁用的条件
            return check_enable_disable_status(logger, task_parameter)
    
    elif event_type == "filter_disabled":
        filter_name = payload.get("filterName")
        if filter_name in expected_filters:
            _FILTERS_DISABLED.add(filter_name)
            logger.info(f"滤镜 '{filter_name}' 已禁用")
            
            # 检查启用和禁用的条件
            return check_enable_disable_status(logger, task_parameter)
    
    elif event_type == "filter_removed":
        filter_name = payload.get("filterName")
        
        if filter_name in expected_filters:
            _FILTERS_REMOVED.add(filter_name)
            logger.info(f"滤镜 '{filter_name}' 已移除")
            
            # 检查是否所有滤镜都已移除
            if all(filter_name in _FILTERS_REMOVED for filter_name in expected_filters):
                logger.info("所有滤镜已成功移除")
                filters_removed = True
                # 检查任务是否完成
                if check_task_completed():
                    return [
                        {"status": "key_step", "index": 3},
                        {"status": "success", "reason": "添加、启用禁用、删除滤镜操作完成"},
                    ]
    return None

def check_enable_disable_status(logger, task_parameter) -> Optional[List[Dict[str, Any]]]:
    """检查滤镜启用和禁用的状态"""
    global _FILTERS_ENABLED, _FILTERS_DISABLED, filters_enabled_disabled
    
    expected_filters = []
    expected_filters = [filter_info["name"] for filter_info in task_parameter["filters"]]
    
    # 检查是否每个滤镜都被启用和禁用过
    if (all(filter_name in _FILTERS_ENABLED for filter_name in expected_filters) and
        all(filter_name in _FILTERS_DISABLED for filter_name in expected_filters)):
        logger.info("所有滤镜已成功启用和禁用")
        filters_enabled_disabled = True
        return [
            {"status": "key_step", "index": 2}
        ]
    return None
        

def check_task_completed():
    """检查任务是否已完成"""
    global filters_added, filters_enabled_disabled, filters_removed
    # 检查所有成功条件
    is_completed = (
        filters_added and
        filters_enabled_disabled and
        filters_removed
    )
    
    return is_completed
