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
content_verified = False

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理来自 Frida 的消息 (send_message task)。
    执行任务特定逻辑判断，并返回状态更新字典列表给 BaseEvaluator。
    """
    global content_verified

    msg_type = message.get('type')
    payload = message.get('payload')
    
    expected_recipient = task_parameter.get('recipient_name', '')
    expected_content = task_parameter.get('message_content', '')

    updates = []

    if msg_type == 'send' and isinstance(payload, dict) and 'event' in payload:
        script_event_name = payload['event']
        logger.debug(f"Handler (SendMsg): 接收到脚本事件: {script_event_name}, Data: {payload.get('message', payload)}")

        if script_event_name == "script_initialized":
            logger.info(f"Handler (SendMsg): 钩子脚本初始化: {payload.get('message', '')}")
            content_verified = False

        elif script_event_name == "function_found":
            logger.info(f"Handler (SendMsg): {payload.get('message', '')} at {payload.get('address', '')}")
        
        elif script_event_name == "send_hook_installed" or script_event_name == "hook_installed":
            logger.info(f"Handler (SendMsg): {payload.get('message', '')}")

        elif script_event_name == "send_function_called":
            logger.info(f"Handler (SendMsg): {payload.get('message', '拦截到消息发送函数调用')}")

        elif script_event_name == "message_detected":
            message_data = payload.get('message_data', {})
            detected_text = message_data.get('text', '')
            detected_peer_name = message_data.get('peer', {}).get('name', '')
            
            logger.info(f"Handler (SendMsg): 检测到发送消息数据 - To: '{detected_peer_name}', Text: '{detected_text[:50]}...'")

            if expected_content.lower() in detected_text.lower() and expected_recipient.lower() in detected_peer_name.lower():
                content_verified = True
                logger.info(f"Handler (SendMsg): 消息内容匹配预期。")
            else:
                content_verified = False
                logger.warning(f"Handler (SendMsg): 检测到的消息内容 '{detected_peer_name}:{detected_text}' 与预期 '{expected_recipient}:{expected_content}' 不符。")


        elif script_event_name == "message_send_completed":
            logger.info(f"Handler (SendMsg): 消息发送函数返回。")
            hook_success = payload.get('success')

            if hook_success is True and content_verified :
                success_message = f"成功向 '{expected_recipient}' 发送消息: '{expected_content}'"
                logger.info(f"Handler (SendMsg): {success_message}")
                updates.append({'status': 'key_step', 'index': 1, 'name': '成功发送消息并验证内容和接收者'})
                updates.append({'status': 'success', 'reason': success_message})
            else:
                reason = []
                if hook_success is not True:
                    reason.append("钩子报告发送未成功完成")
                if not content_verified:
                    reason.append("消息内容不匹配")
                fail_message = f"消息发送未满足所有条件: {'; '.join(reason)}."
                logger.error(f"Handler (SendMsg): {fail_message}")
                # 可选: 如果验证失败，则报告错误状态
                # updates.append({'status': 'error', 'type': 'send_validation_failed', 'message': fail_message})

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