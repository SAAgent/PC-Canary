#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, Callable

# 全局评估器实例，由message_handler使用
_EVALUATOR = None
_CONFIG = None
_START_TIME = None

# 追踪滤镜相关状态
_FILTERS_ADDED = set()
_FILTERS_ENABLED = set()
_FILTERS_DISABLED = set()
_FILTERS_REMOVED = set()

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator
    
    # 使用评估器的已更新配置，而不是重新读取文件
    if hasattr(evaluator, 'config') and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("使用评估器中的更新配置")
    else:
        # 作为备份，如果评估器中没有配置，才从文件读取
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "config.json")
            
            with open(config_file, 'r') as f:
                _CONFIG = json.load(f)
                _EVALUATOR.logger.info("从文件加载配置")
        except Exception as e:
            if _EVALUATOR:
                _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")
            # 提供一个默认配置以避免空引用
            _CONFIG = {"task_parameters": {
                "text_source_name": "text_src",
                "filters": [
                    {
                        "name": "f1",
                        "type": "color_key_filter"
                    },
                    {
                        "name": "f2",
                        "type": "scroll_filter"
                    }
                ]
            }}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: injector消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _EVALUATOR, _CONFIG, _START_TIME, _FILTERS_ADDED, _FILTERS_ENABLED, _FILTERS_DISABLED, _FILTERS_REMOVED
    
    # 初始化开始时间
    if _START_TIME is None:
        _START_TIME = time.time()
    
    # 检查评估器是否已设置
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None
    
    # 获取期望的滤镜信息
    expected_filters = []
    filter_types_map = {}  # 用于存储滤镜名称和类型的映射
    
    if _CONFIG and "task_parameters" in _CONFIG and "filters" in _CONFIG["task_parameters"]:
        expected_filters = [filter_info["name"] for filter_info in _CONFIG["task_parameters"]["filters"]]
        
        # 创建滤镜名称到滤镜类型的映射
        for filter_info in _CONFIG["task_parameters"]["filters"]:
            filter_types_map[filter_info["name"]] = filter_info["type"]
    
    # 处理从hooker.js发送过来的事件
    payload = message.get("payload", {})
    event_type = payload.get("event")
    
    _EVALUATOR.logger.info(f"接收到事件: {event_type}, 负载: {payload}")
    
    if event_type == "script_initialized":
        _EVALUATOR.update_metric("script_initialized", True)
        return None
    
    elif event_type == "filter_created":
        filter_name = payload.get("filterName")
        source_name = payload.get("sourceName")
        filter_kind = payload.get("filterKind")
        
        if filter_name in expected_filters:
            # 检查滤镜类型是否匹配
            expected_type = filter_types_map.get(filter_name)
            
            if expected_type and filter_kind:
                if expected_type in filter_kind or filter_kind in expected_type:
                    _EVALUATOR.logger.info(f"滤镜 '{filter_name}' 类型匹配成功: 期望 '{expected_type}', 实际 '{filter_kind}'")
                    _FILTERS_ADDED.add(filter_name)
                    _EVALUATOR.logger.info(f"滤镜 '{filter_name}' 已添加到源 '{source_name}'")
                    _EVALUATOR.update_metric("filter_created", True)
                else:
                    _EVALUATOR.logger.warning(f"滤镜 '{filter_name}' 类型不匹配: 期望 '{expected_type}', 实际 '{filter_kind}'")
            else:
                # 如果没有类型信息，则仅基于名称检查
                _FILTERS_ADDED.add(filter_name)
                _EVALUATOR.logger.info(f"滤镜 '{filter_name}' 已添加到源 '{source_name}'，但未进行类型检查")
                _EVALUATOR.update_metric("filter_created", True)
            
            # 检查是否所有滤镜都已添加
            if all(filter_name in _FILTERS_ADDED for filter_name in expected_filters):
                _EVALUATOR.logger.info("所有滤镜已成功添加")
                _EVALUATOR.update_metric("filters_added", True)
    
    elif event_type == "filter_enabled":
        filter_name = payload.get("filterName")
        if filter_name in expected_filters:
            _FILTERS_ENABLED.add(filter_name)
            _EVALUATOR.logger.info(f"滤镜 '{filter_name}' 已启用")
            _EVALUATOR.update_metric("filter_enabled", True)
            
            # 检查启用和禁用的条件
            check_enable_disable_status()
    
    elif event_type == "filter_disabled":
        filter_name = payload.get("filterName")
        if filter_name in expected_filters:
            _FILTERS_DISABLED.add(filter_name)
            _EVALUATOR.logger.info(f"滤镜 '{filter_name}' 已禁用")
            _EVALUATOR.update_metric("filter_disabled", True)
            
            # 检查启用和禁用的条件
            check_enable_disable_status()
    
    elif event_type == "filter_removed":
        filter_name = payload.get("filterName")
        
        if filter_name in expected_filters:
            _FILTERS_REMOVED.add(filter_name)
            _EVALUATOR.logger.info(f"滤镜 '{filter_name}' 已移除")
            _EVALUATOR.update_metric("filter_removed", True)
            
            # 检查是否所有滤镜都已移除
            if all(filter_name in _FILTERS_REMOVED for filter_name in expected_filters):
                _EVALUATOR.logger.info("所有滤镜已成功移除")
                _EVALUATOR.update_metric("filters_removed", True)
    
    elif event_type == "error":
        error_type = payload.get("error_type")
        error_message = payload.get("message")
        _EVALUATOR.logger.error(f"错误类型: {error_type}, 错误消息: {error_message}")
        _EVALUATOR.update_metric("error", True)
    
    # 检查任务是否完成
    if check_task_completed():
        completion_time = time.time() - _START_TIME
        _EVALUATOR.update_metric("time_to_complete", completion_time)
        _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
        return "success"
    
    return None

def check_enable_disable_status():
    """检查滤镜启用和禁用的状态"""
    global _EVALUATOR, _CONFIG, _FILTERS_ENABLED, _FILTERS_DISABLED
    
    expected_filters = []
    if _CONFIG and "task_parameters" in _CONFIG and "filters" in _CONFIG["task_parameters"]:
        expected_filters = [filter_info["name"] for filter_info in _CONFIG["task_parameters"]["filters"]]
    
    # 检查是否每个滤镜都被启用和禁用过
    if (all(filter_name in _FILTERS_ENABLED for filter_name in expected_filters) and
        all(filter_name in _FILTERS_DISABLED for filter_name in expected_filters)):
        _EVALUATOR.logger.info("所有滤镜已成功启用和禁用")
        _EVALUATOR.update_metric("filters_enabled_disabled", True)

def check_task_completed():
    """检查任务是否已完成"""
    global _EVALUATOR
    
    if not _EVALUATOR:
        return False
    
    # 检查所有成功条件
    is_completed = (
        _EVALUATOR.metrics.get("filters_added", False) and
        _EVALUATOR.metrics.get("filters_enabled_disabled", False) and
        _EVALUATOR.metrics.get("filters_removed", False)
    )
    
    return is_completed

def register_handlers(evaluator):
    """
    注册所有事件处理函数到评估器
    
    Args:
        evaluator: 评估器实例
        
    Returns:
        message_handler: 处理函数
    """
    # 设置全局评估器，用于message_handler
    set_evaluator(evaluator)
    return message_handler