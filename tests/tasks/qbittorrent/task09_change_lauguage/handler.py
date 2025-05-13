#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
qBittorrent更改语言任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理来自 Frida 的消息。
    执行任务特定逻辑判断，并返回状态更新字典列表给 BaseEvaluator。

    Args:
        message: 消息对象
        logger: 日志记录器
        task_parameter: 任务参数

    Returns:
        一个包含状态更新字典的列表，或 None。
        可能的字典状态 ('status'): 'success', 'error', 'key_step', 'app_event'
    """
    msg_type = message.get('type')
    payload = message.get('payload')
    target_language = task_parameter.get('target_language', 'zh')  # 默认目标语言为中文

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
            # 报告关键步骤 1 完成
            updates.append({'status': 'key_step', 'index': 1})

        elif script_event_name == "change_language_called":
            requested_locale = payload.get("requested_locale", "")
            logger.info(f"Handler: 拦截到更改语言的函数调用，请求语言: {requested_locale}")
            # 报告关键步骤 2 完成
            updates.append({'status': 'key_step', 'index': 2})

        elif script_event_name == "change_language_result":
            locale = payload.get("locale", "")
            logger.info(f"Handler: 语言已更改为: {locale}")
            
            # 检查设置的语言是否符合预期
            # 这里我们检查locale中是否包含目标语言代码
            # 中文可能是zh_CN, zh_TW等
            if target_language in locale.lower():
                success_message = f"成功将界面语言更改为 {locale}"
                logger.info(f"Handler: {success_message}")
                # 报告关键步骤 3 完成
                updates.append({'status': 'key_step', 'index': 3})
                updates.append({'status': 'success', 'reason': success_message})
                updates.append({
                    'status': 'app_event', 
                    'name': 'change_language_result',
                    'data': {'locale': locale}
                })
            else:
                logger.warning(f"Handler: 设置的语言 {locale} 与目标语言 {target_language} 不符")
                # 仍然报告步骤完成，但不报告成功
                updates.append({'status': 'key_step', 'index': 3})

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
