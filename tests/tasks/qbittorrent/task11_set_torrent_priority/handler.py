#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
qBittorrent设置种子优先级任务事件处理器
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
    target_priority = task_parameter.get('target_priority', 'High')
    priority_values = task_parameter.get('priority_values', {
        'Ignored': 0,
        'Normal': 1,
        'High': 6,
        'Maximum': 7
    })
    torrent_source = task_parameter.get('torrent_source', '')
    expected_torrent_name = task_parameter.get('torrent_name', '')

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

        elif script_event_name == "set_torrent_priority_before":
            logger.info(f"Handler: 拦截到设置种子优先级函数")
            # 报告关键步骤 2 完成
            torrent_name = payload.get("torrent_name", "")
            torrent_priority = payload.get("torrent_priority", "")
            updates.append({'status': 'key_step', 'index': 2})
            updates.append({'status': 'current_torrent_priority', 'reason': f"当前种子名称: {torrent_name}, 当前种子优先级: {torrent_priority}"})

        elif script_event_name == "set_torrent_priority_after":
            logger.info(f"Handler: 成功设置种子优先级")
            # 报告关键步骤 3 完成
            updates.append({'status': 'key_step', 'index': 3})
            
            # 获取种子名称和优先级信息
            torrent_name = payload.get("torrent_name", "")
            torrent_priority = payload.get("torrent_priority", "")
            
            if torrent_name or torrent_priority:
                logger.info(f"Handler: 种子名称: {torrent_name}, 设置优先级: {torrent_priority}")
                
                # 检查优先级设置是否成功
                if torrent_priority == target_priority:
                    success_message = f"成功将种子 '{torrent_name}' 的优先级设置为 {torrent_priority}"
                    logger.info(f"Handler: {success_message}")
                    
                    # 报告关键步骤 3 完成
                    updates.append({'status': 'key_step', 'index': 3})
                    updates.append({'status': 'success', 'reason': success_message})
                    updates.append({
                        'status': 'app_event', 
                        'name': 'set_torrent_priority_result',
                        'data': {'torrent_name': torrent_name, 'priority': torrent_priority}
                    })
                else:
                    # 检查数值是否匹配目标优先级
                    target_value = priority_values.get(target_priority)
                 
                    current_value = None
                    
                    # 尝试获取当前优先级的数值
                    for name, value in priority_values.items():
                        if name == torrent_priority:
                            current_value = value
                            break
                    logger.info(f"torrent_name: {torrent_name}, expected_torrent_name: {expected_torrent_name}")
                    if current_value is not None and current_value == target_value and torrent_name == expected_torrent_name:
                        success_message = f"成功将种子 '{torrent_name}' 的优先级设置为 {torrent_priority}（值匹配目标）"
                        logger.info(f"Handler: {success_message}")
                        
                        # 报告关键步骤 3 完成
                        updates.append({'status': 'key_step', 'index': 3})
                        updates.append({'status': 'success', 'reason': success_message})
                        updates.append({
                            'status': 'app_event', 
                            'name': 'set_torrent_priority_result',
                            'data': {'torrent_name': torrent_name, 'priority': torrent_priority}
                        })
                    else:
                        logger.warning(f"Handler: 设置的优先级 {torrent_priority} 与目标优先级 {target_priority} 不符")
                        # 仍然报告步骤完成，可能是名称不同但值相同的情况
                        updates.append({'status': 'key_step', 'index': 3})
            else:
                logger.warning("Handler: 未能获取种子名称或优先级信息")

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

