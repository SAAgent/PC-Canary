#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
qBittorrent选择性下载种子文件任务事件处理器
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
    # torrent_name = task_parameter.get('torrent_name', '')
    file_names = task_parameter.get('file_names', [])

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

        elif script_event_name == "file_selection_detected":
         
            detected_torrent = payload.get("torrent_name", "")
            priority_name = payload.get("priority_name", "")
            logger.info(f"Handler: 检测到文件选择操作: {detected_torrent}")
            
            # 检查是否是目标种子
            
            logger.info(f"Handler: 在目标种子中检测到文件选择: {detected_torrent}")
            updates.append({'status': 'key_step', 'index': 2})
            updates.append({
                'status': 'app_event',
                'name': 'file_selection_detected',
                'data': {'torrent_name': detected_torrent, 'priority_name': priority_name}
            })
           

        elif script_event_name == "file_selection_finished":
            detected_torrent = payload.get("torrent_name", "")
            priority_name = payload.get("priority_name", "")
            logger.info(f"Handler: 文件选择操作结束: 种子 {detected_torrent}")
            updates.append({'status': 'key_step', 'index': 3})
            updates.append({
                'status': 'app_event',
                'name': 'file_selection_finished',
                'data': {'torrent_name': detected_torrent, 'priority_name': priority_name}
            })

        elif script_event_name == "file_download_started":
            detected_torrents = payload.get("selected_files", [])
            logger.info(f"Handler: 文件开始下载: 种子 {detected_torrents}")
            
            # 检查是否是目标种子和文件
            matched_files = [f for f in file_names if f in detected_torrents]
            if len(detected_torrents) == len(matched_files) and matched_files:
                success_message = f"成功开始下载文件: {detected_torrents}"
                logger.info(f"Handler: {success_message}")
                
                # 报告关键步骤 3 完成
                updates.append({'status': 'key_step', 'index': 3})
                updates.append({'status': 'success', 'reason': success_message})
                updates.append({
                    'status': 'app_event',
                    'name': 'file_download_started',
                    'data': {'torrent_name': detected_torrents}
                })
            else:
                logger.debug(f"Handler: 下载的文件: {detected_torrents} 不匹配目标: {file_names}")

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