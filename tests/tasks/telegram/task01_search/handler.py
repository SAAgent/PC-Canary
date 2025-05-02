#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram搜索任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, List

# 全局评估器实例，由message_handler使用
_EVALUATOR = None
_CONFIG = None
_TARGET_QUERY = ""

def set_evaluator(evaluator):
    """设置全局评估器实例并加载配置"""
    global _EVALUATOR, _CONFIG, _TARGET_QUERY
    _EVALUATOR = evaluator

    if hasattr(evaluator, "config") and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("Handler (Search): 使用评估器中的更新配置")
        _TARGET_QUERY = _CONFIG.get("task_parameters", {}).get("query", "")
        if not _TARGET_QUERY:
             _EVALUATOR.logger.warning("Handler (Search): 任务参数 'query' 未在配置中找到！")
    else:
        _EVALUATOR.logger.error("Handler (Search): 评估器配置未加载，无法运行任务。")
        _CONFIG = {}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[List[Dict[str, Any]]]:
    """
    处理来自 Frida 的消息。
    执行搜索任务特定逻辑判断，并返回状态更新字典列表给 BaseEvaluator。

    Args:
        message: 消息对象
        data: 附加数据

    Returns:
        一个包含状态更新字典的列表，或 None。
    """
    global _EVALUATOR, _CONFIG, _TARGET_QUERY

    if _EVALUATOR is None:
        print("严重警告: 评估器未设置，无法处理消息！")
        return [{'status': 'error', 'type': 'handler_setup', 'message': 'Evaluator not set'}]

    msg_type = message.get('type')
    payload = message.get('payload')

    updates = []

    if msg_type == 'send' and isinstance(payload, dict) and 'event' in payload:
        script_event_name = payload['event']
        _EVALUATOR.logger.debug(f"Handler (Search): 接收到脚本事件: {script_event_name}, Payload: {payload}")

        if script_event_name == "script_initialized":
            _EVALUATOR.logger.info(f"Handler (Search): 钩子脚本初始化: {payload.get('message', '')}")

        elif script_event_name == "search_function_found":
            _EVALUATOR.logger.info(f"Handler (Search): 找到搜索函数: {payload.get('message', '')}")

        elif script_event_name == "search_query_detected":
            invoked_query = payload.get("query", "")
            _EVALUATOR.logger.info(f"Handler (Search): 检测到搜索查询: {invoked_query}")

            query_match = False
            if _TARGET_QUERY.lower() in invoked_query.lower():
                query_match = True

            if query_match:
                success_message = f"搜索 '{_TARGET_QUERY}' 成功。"
                updates.append({'status': 'key_step', 'index': 1})
                updates.append({'status': 'success', 'reason': success_message})
            else:
                _EVALUATOR.logger.info(f"Handler (Search): 收到的搜索结果 '{invoked_query}' 与目标查询 '{_TARGET_QUERY}' 不匹配。")

        elif script_event_name == "error":
            error_type = payload.get("error_type", "script_error")
            message_text = payload.get("message", "未知脚本错误")
            error_reason = f"钩子脚本错误 ({error_type}): {message_text}"
            _EVALUATOR.logger.error(f"Handler (Search): {error_reason}")
            updates.append({
                'status': 'error',
                'type': error_type,
                'message': message_text
            })

        return updates if updates else None

    elif msg_type == 'error':
        stack_trace = message.get('stack', '')
        error_description = message.get('description', '未知 Frida 错误')
        error_reason = f"Frida JS 错误: {error_description}"
        _EVALUATOR.logger.error(f"Handler (Search): {error_reason}\nStack: {stack_trace}")
        return [{
            'status': 'error',
            'type': 'Frida Error',
            'message': error_description,
            'stack_trace': stack_trace
        }]

    return None

def register_handlers(evaluator):
    """注册消息处理器并设置评估器实例"""
    set_evaluator(evaluator)
    return message_handler
