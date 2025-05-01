#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram搜索任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional

# 导入 AgentEvent
from evaluator.core.events import AgentEvent

# 全局评估器实例，由message_handler使用
_EVALUATOR = None
_CONFIG = None
_START_TIME = None

# 预期参数
_EXPECTED_QUERY = ""

def set_evaluator(evaluator):
    """设置全局评估器实例并加载配置"""
    global _EVALUATOR, _CONFIG, _EXPECTED_QUERY
    _EVALUATOR = evaluator

    if hasattr(evaluator, "config") and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("Search Handler: 使用评估器中的更新配置")
        # 从配置加载预期参数
        _EXPECTED_QUERY = _CONFIG.get("task_parameters", {}).get("query", "")
        _EVALUATOR.logger.info(f"Search Handler: 预期查询: {_EXPECTED_QUERY}")
        if not _EXPECTED_QUERY:
             _EVALUATOR.logger.warning("Search Handler: 任务参数 'query' 未在配置中找到！")
    else:
        _EVALUATOR.logger.error("Search Handler: 评估器配置未加载，无法运行任务。")
        _CONFIG = {}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理来自 HookManager 的消息。
    记录 AgentEvents 到 ResultCollector。
    返回 "success" 或 "error" 字符串给 BaseEvaluator 以触发回调。
    """
    global _EVALUATOR, _CONFIG, _START_TIME, _EXPECTED_QUERY

    if _EVALUATOR is None:
        print("严重警告: Search Handler - 评估器未设置！")
        return "error"

    if _START_TIME is None:
        _START_TIME = time.time()
        _EVALUATOR.record_event(AgentEvent.TASK_START, {'timestamp': _START_TIME})
        _EVALUATOR.logger.info("Search Handler: 任务计时开始")

    msg_type = message.get('type')
    payload = message.get('payload')
    current_time = time.time()

    if msg_type == 'send' and isinstance(payload, dict) and 'event' in payload:
        script_event_name = payload['event']
        _EVALUATOR.logger.debug(f"Search Handler: 接收到脚本事件: {script_event_name}, Payload: {payload}")

        # 记录通用的 APP_SPECIFIC_EVENT
        _EVALUATOR.record_event(
            AgentEvent.APP_SPECIFIC_EVENT,
            {'timestamp': current_time, 'name': script_event_name, 'payload': payload}
        )

        # --- 根据脚本事件类型执行特定逻辑 --- #

        if script_event_name == "script_initialized":
            _EVALUATOR.logger.info(f"Search Handler: 钩子脚本初始化: {payload.get('message', '')}")

        elif script_event_name == "search_query_detected":
            invoked_query = payload.get("query", "")

            # 检查查询是否与预期匹配
            if invoked_query.lower() == _EXPECTED_QUERY.lower():
                step_name = "搜索结果更新并匹配"
                success_message = f"成功检测到预期搜索查询: '{_EXPECTED_QUERY}'"
                _EVALUATOR.logger.info(f"Search Handler: {success_message}")

                # 记录关键步骤 1 完成
                _EVALUATOR.record_event(AgentEvent.KEY_STEP_COMPLETED, {
                    'timestamp': current_time,
                    'step_index': 1,
                    'step_name': step_name
                })

                # 记录任务成功结束事件
                _EVALUATOR.record_event(AgentEvent.TASK_END, {
                    'timestamp': current_time,
                    'status': 'success',
                    'reason': success_message
                })

                # 返回 "success" 给 BaseEvaluator
                return "success"
            else:
                _EVALUATOR.logger.info(f"Search Handler: 检测到搜索查询 '{invoked_query}', 但不匹配预期 '{_EXPECTED_QUERY}'")

        elif script_event_name == "error":
            error_type = payload.get("error_type", "script_error")
            message = payload.get("message", "未知脚本错误")
            error_reason = f"钩子脚本错误 ({error_type}): {message}"
            _EVALUATOR.logger.error(f"Search Handler: {error_reason}")

            _EVALUATOR.record_event(AgentEvent.AGENT_ERROR_OCCURRED, {
                'timestamp': current_time, 'error': error_type, 'message': message
            })
            _EVALUATOR.record_event(AgentEvent.TASK_END, {
                'timestamp': current_time, 'status': 'failure', 'reason': error_reason
            })
            return "error"

    elif msg_type == 'error':
        stack_trace = message.get('stack', '')
        error_description = message.get('description', '未知 Frida 错误')
        error_reason = f"Frida JS 错误: {error_description}"
        _EVALUATOR.logger.error(f"Search Handler: {error_reason}\nStack: {stack_trace}")

        _EVALUATOR.record_event(AgentEvent.AGENT_ERROR_OCCURRED, {
            'timestamp': current_time, 'error': 'Frida Error', 'message': error_description, 'stack_trace': stack_trace
        })
        _EVALUATOR.record_event(AgentEvent.TASK_END, {
            'timestamp': current_time, 'status': 'failure', 'reason': error_reason
        })
        return "error"

    return None

def register_handlers(evaluator):
    """注册消息处理器并设置评估器实例"""
    set_evaluator(evaluator)
    return message_handler
