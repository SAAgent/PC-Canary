#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
qBittorrent修改种子路径任务事件处理器
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
    expected_torrent_name = task_parameter.get('torrent_name')
    expected_new_path = task_parameter.get('new_path')

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
            updates.append({'status': 'key_step', 'index': 1})

        elif script_event_name == "change_torrent_path_called":
            torrent_name = payload.get("name", "")
            save_path_before = payload.get("save_path_before", "")
            logger.info(f"Handler: 拦截到修改路径函数调用，种子名称: {torrent_name}, 原路径: {save_path_before}")
            # No status update needed

        elif script_event_name == "change_torrent_path_success":
            torrent_name = payload.get("name", "")
            save_path_after = payload.get("save_path_after", "")
            
            logger.info(f"Handler: 种子: {torrent_name}, 新路径: {save_path_after}")
            
            if torrent_name and expected_torrent_name in torrent_name and expected_new_path in save_path_after:
                success_message = f"成功修改种子 {torrent_name} 的保存路径为 {save_path_after}"
                logger.info(f"Handler: {success_message}")
                # 报告关键步骤 2 完成
                updates.append({'status': 'key_step', 'index': 2})
                updates.append({'status': 'success', 'reason': success_message})
            else:
                logger.debug(f"Handler: 种子名称或路径不匹配。种子名称: {torrent_name}, 目标种子: {expected_torrent_name}, 目标路径: {expected_new_path}, 实际路径: {save_path_after}")
                # 不是目标种子或路径不符，此事件不代表任何状态更新

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