#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram 发送消息任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

# Module-level state variables to store interim results between events
# These should ideally be reset at the beginning of each task evaluation run by the evaluator,
# or by a specific event like 'script_initialized' if the handler instance persists.

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理来自 Frida 的消息 (send_message task)。
    执行任务特定逻辑判断，并返回状态更新字典列表给 BaseEvaluator。
    """
    global file_path_verified

    msg_type = message.get('type')
    payload = message.get('payload')
    expected_add = task_parameter.get("ml_type", "")
    

    updates = []

    if msg_type == 'send' and isinstance(payload, dict) and 'event' in payload:
        script_event_name = payload['event']
        logger.debug(f"Handler (SendMsg): 接收到脚本事件: {script_event_name}, Data: {payload.get('message', payload)}")

        if script_event_name == "script_initialized":
            logger.info(f"Handler (SendMsg): 钩子脚本初始化: {payload.get('message', '')}")
            file_path_verified = False

        elif script_event_name == "function_found":
            logger.info(f"Handler (SendMsg): {payload.get('message', '')} at {payload.get('address', '')}")
        
        elif script_event_name == "hook_installed":
            logger.info(f"Handler (SendMsg): {payload.get('message', '')}")

        elif script_event_name == "add_element_detected":
            query = payload.get("name", "")
            
            logger.info(f"Handler (SendMsg): 检测到增加元素: {query}")

            if query.lower() == expected_add.lower():
                success_message = f"成功增加元素 '{expected_add}'"
                logger.info(f"Handler (SendMsg): {success_message}")
                updates.append({'status': 'key_step', 'index': 1, 'name': '成功增加元素并验证元素类型'})
                updates.append({'status': 'success', 'reason': success_message})
            else:
                reason = []
                reason.append("元素类型不匹配")
                fail_message = f"元素增加未满足所有条件: {'; '.join(reason)}."
                logger.error(f"Handler (SendMsg): {fail_message}")

        elif script_event_name == "error":
            error_type = payload.get("error_type", "script_error")
            message_text = payload.get("message", "未知脚本错误")
            error_reason = f"钩子脚本错误 ({error_type}): {message_text}"
            logger.error(f"Handler (SendMsg): {error_reason}")
            updates.append({
                'status': 'error',
                'type': error_type,
                'message': message_text,
                'stack_trace': payload.get('stack')
            })
        
        return updates if updates else None

    elif msg_type == 'error':
        stack_trace = message.get('stack', '')
        error_description = message.get('description', '未知 Frida 错误')
        error_reason = f"Frida JS 错误: {error_description}"
        logger.error(f"Handler (SendMsg): {error_reason}\nStack: {stack_trace}")
        return [{
            'status': 'error',
            'type': 'Frida Error',
            'message': error_description,
            'stack_trace': stack_trace
        }]

    return None 