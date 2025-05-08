#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram搜索任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理来自 Frida 的消息。
    执行搜索任务特定逻辑判断，并返回状态更新字典列表给 BaseEvaluator。

    Args:
        message: 消息对象
        data: 附加数据

    Returns:
        一个包含状态更新字典的列表，或 None。
    """
    msg_type = message.get('type')
    payload = message.get('payload')
    target_query = task_parameter.get('query')

    updates = []

    if msg_type == 'send' and isinstance(payload, dict) and 'event' in payload:
        script_event_name = payload['event']
        logger.debug(f"Handler (Search): 接收到脚本事件: {script_event_name}, Payload: {payload}")

        if script_event_name == "script_initialized":
            logger.info(f"Handler (Search): 钩子脚本初始化: {payload.get('message', '')}")

        elif script_event_name == "search_function_found":
            logger.info(f"Handler (Search): 找到搜索函数: {payload.get('message', '')}")

        elif script_event_name == "search_query_detected":
            invoked_query = payload.get("query", "")
            logger.info(f"Handler (Search): 检测到搜索查询: {invoked_query}")

            query_match = False
            if target_query.lower() in invoked_query.lower():
                query_match = True

            if query_match:
                success_message = f"搜索 '{target_query}' 成功。"
                updates.append({'status': 'key_step', 'index': 1})
                updates.append({'status': 'success', 'reason': success_message})
            else:
                logger.info(f"Handler (Search): 收到的搜索结果 '{invoked_query}' 与目标查询 '{target_query}' 不匹配。")

        elif script_event_name == "error":
            error_type = payload.get("error_type", "script_error")
            message_text = payload.get("message", "未知脚本错误")
            error_reason = f"钩子脚本错误 ({error_type}): {message_text}"
            logger.error(f"Handler (Search): {error_reason}")
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
        logger.error(f"Handler (Search): {error_reason}\nStack: {stack_trace}")
        return [{
            'status': 'error',
            'type': 'Frida Error',
            'message': error_description,
            'stack_trace': stack_trace
        }]

    return None
