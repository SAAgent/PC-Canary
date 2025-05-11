#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram 暗黑模式切换任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

first_check = True
night_mode_switched = False

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理来自 Frida 的消息。
    执行暗黑模式任务特定逻辑判断，并返回状态更新字典列表给 BaseEvaluator。

    Args:
        message: 消息对象，包含 type 和 payload
        logger: 日志记录器实例
        task_parameter: 任务参数，例如 {"target_mode": "dark"}

    Returns:
        一个包含状态更新字典的列表，或 None。
        可能的字典状态 ('status'): 'success', 'error', 'key_step', 'app_event'
    """
    global first_check, night_mode_switched

    msg_type = message.get('type')
    payload = message.get('payload')
    target_mode = task_parameter.get('target_mode', 'dark') # 'dark' or 'light'

    updates = []

    if msg_type == 'send' and isinstance(payload, dict) and 'event' in payload:
        script_event_name = payload['event']
        logger.debug(f"Handler (DarkMode): 接收到脚本事件: {script_event_name}, Payload: {payload}")

        if script_event_name == "script_initialized":
            logger.info(f"Handler (DarkMode): 钩子脚本初始化: {payload.get('message', '')}")

        elif script_event_name == "hook_installed":
            logger.info(f"Handler (DarkMode): 暗黑模式监控钩子安装完成: {payload.get('message', '')}")
        
        elif script_event_name == "function_found":
            logger.info(f"Handler (DarkMode): 找到函数: {payload.get('function_name', '')} at {payload.get('address', '')}")

        elif script_event_name == "night_mode_status_checked":
            is_night_mode = payload.get('isNightMode')
            logger.info(f"Handler (DarkMode): 主动检查夜间模式状态: {is_night_mode}")
            
            # 如果是首次调用且不与 target mode 相反，报错退出
            if first_check and (target_mode == 'dark' and is_night_mode is True) or \
               (target_mode == 'light' and is_night_mode is False):
                logger.error(f"Handler (DarkMode): 检测到初始状态已为目标模式 ('{target_mode}').")
                failed_message = f"初始状态已是目标模式 '{target_mode}'。"
                updates.append({'status': 'error', 'type': 'initial_state_error', 'message': failed_message})
                return updates
            else:
                first_check = False

        elif script_event_name == "write_settings_called":
            logger.info(f"Handler (DarkMode): {payload.get('message', '')}")
            updates.append({'status': 'key_step', 'index': 1, 'name': '设置项被触发更新'}) 

        elif script_event_name == "night_mode_setting_detected":
            is_night_mode = payload.get('isNightMode')
            if (target_mode == "dark" and is_night_mode == 1) or \
               (target_mode == "light" and is_night_mode == 0):
                night_mode_switched = True
                logger.info(f"Handler (DarkMode): 主题模式已更新")
            else:
                night_mode_switched = False
                logger.info(f"Handler (DarkMode): 主题模式并未更新")

            
        elif script_event_name == "settings_write_allowed":
            logger.info(f"Handler (DarkMode): 检测到设置项将被保存: {payload.get('message', '')}")

        elif script_event_name == "write_settings_returned":
            logger.info(f"Handler (DarkMode): {payload.get('message', '')}")
            if night_mode_switched:
                success_message = "成功切换主题模式，设置已经保存"
                updates.append({'status': 'key_step', 'index': 2, 'name': '确认新设置中主题切换'})
                updates.append({'status': 'success', 'reason': success_message})
        
        elif script_event_name == "error":
            error_type = payload.get("error_type", "script_error")
            message_text = payload.get("message", "未知脚本错误")
            error_reason = f"钩子脚本错误 ({error_type}): {message_text}"
            logger.error(f"Handler (DarkMode): {error_reason}")
            updates.append({
                'status': 'error',
                'type': error_type,
                'message': message_text
            })
        
        return updates if updates else None

    elif msg_type == 'error': # Frida 内部错误
        stack_trace = message.get('stack', '')
        error_description = message.get('description', '未知 Frida 错误')
        error_reason = f"Frida JS 错误: {error_description}"
        logger.error(f"Handler (DarkMode): {error_reason}\nStack: {stack_trace}")
        return [{
            'status': 'error',
            'type': 'Frida Error',
            'message': error_description,
            'stack_trace': stack_trace
        }]

    return None
