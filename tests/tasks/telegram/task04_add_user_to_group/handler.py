#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram添加用户到群组任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理来自 Frida 的消息。
    执行任务特定逻辑判断，并返回状态更新字典列表给 BaseEvaluator。

    Args:
        message: 消息对象
        data: 附加数据

    Returns:
        一个包含状态更新字典的列表，或 None。
        可能的字典状态 ('status'): 'success', 'error', 'key_step', 'app_event'
    """
    msg_type = message.get('type')
    payload = message.get('payload')
    expected_user = task_parameter.get('user_to_add')
    expected_group = task_parameter.get('group_name')

    # 处理来自 Frida 脚本的 'send' 类型消息
    if msg_type == 'send' and isinstance(payload, dict) and 'event' in payload:
        script_event_name = payload['event']
        logger.debug(f"Handler: 接收到脚本事件: {script_event_name}, Payload: {payload}")

        # --- 根据脚本事件类型执行特定逻辑 --- #
        updates = [] # Initialize list for updates from this message

        if script_event_name == "script_initialized":
            logger.info(f"Handler: 钩子脚本初始化: {payload.get('message', '')}")
            # No status update to return for this event

        elif script_event_name == "function_found":
            logger.info(f"Handler: 找到函数地址: {payload.get('address', '')}")
            # No status update needed

        elif script_event_name == "apply_chat_update_called":
            logger.info("Handler: 拦截到本地群组状态更新函数调用")
            # No status update needed

        elif script_event_name == "participants_count":
            count = payload.get("count", 0)
            logger.info(f"Handler: 群组当前有 {count} 个成员")
            # No status update needed

        elif script_event_name == "chatinfo_updated":
            chat_name = payload.get("chat_name", "")
            participants = payload.get("participants", [])
            logger.info(f"Handler: 收到群组更新 - 名称: '{chat_name}', 成员: {participants}")

            # 判断是否关键步骤 1 完成 (找到目标群组)
            if chat_name.lower() == expected_group.lower():
                logger.info(f"Handler: 匹配到目标群组: '{chat_name}'")
                # 报告关键步骤 1 完成
                updates.append({'status': 'key_step', 'index': 1})
                # Name is optional here, BaseEvaluator can get default from config

                # 判断是否关键步骤 2 完成 (用户已添加)
                user_found = any(p.lower() == expected_user.lower() for p in participants)
                if user_found:
                    success_message = f"目标用户 '{expected_user}' 已成功添加到群组 '{chat_name}'"
                    logger.info(f"Handler: {success_message}")
                    # 报告关键步骤 2 完成
                    updates.append({'status': 'key_step', 'index': 2})
                    # 报告任务成功
                    updates.append({'status': 'success', 'reason': success_message})
                else:
                    logger.info(f"Handler: 目标用户 '{expected_user}' 尚未在群组 '{chat_name}' 成员列表中。")
                    # 仅报告步骤 1 完成 (已在上面添加)
            else:
                logger.debug(f"Handler: 收到的群组 '{chat_name}' 不是目标群组 '{expected_group}'。")
                # 不是目标群组，此事件不代表任何状态更新

        elif script_event_name == "error": # 来自应用的错误事件
            error_type = payload.get("error_type", "script_error")
            message_text = payload.get("message", "未知脚本错误")
            error_reason = f"钩子脚本错误 ({error_type}): {message_text}"
            logger.error(f"Handler: {error_reason}")
            # 报告错误状态
            updates.append({
                'status': 'error',
                'type': error_type,
                'message': message_text
            })

        # Return the list of updates if any were added
        return updates if updates else None

    # 处理来自 Frida 的 'error' 类型消息
    elif msg_type == 'error':
        stack_trace = message.get('stack', '')
        error_description = message.get('description', '未知 Frida 错误')
        error_reason = f"Frida JS 错误: {error_description}"
        logger.error(f"Handler: {error_reason}\nStack: {stack_trace}")
        # 报告错误状态
        return [{
            'status': 'error',
            'type': 'Frida Error',
            'message': error_description,
            'stack_trace': stack_trace
        }]

    # 如果消息类型不是 'send' 或 'error'，或者没有触发任何逻辑，则返回 None
    return None
