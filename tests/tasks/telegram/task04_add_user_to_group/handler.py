#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram添加用户到群组任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional

# 导入 AgentEvent
from evaluator.core.events import AgentEvent

_EVALUATOR = None
_CONFIG = None
_START_TIME = None

# 用于映射配置中的参数名到变量
_EXPECTED_USER = ""
_EXPECTED_GROUP = ""


def set_evaluator(evaluator):
    """设置全局评估器实例并加载配置"""
    global _EVALUATOR, _EVALUATOR, _CONFIG, _EXPECTED_USER, _EXPECTED_GROUP
    _EVALUATOR = evaluator

    if hasattr(evaluator, "config") and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("Handler: 使用评估器中的更新配置")
        # 从加载的配置中获取期望参数 (与 config.json 中的 task_parameters 对应)
        _EXPECTED_USER = _CONFIG.get("task_parameters", {}).get("user_to_add", "")
        _EXPECTED_GROUP = _CONFIG.get("task_parameters", {}).get("group_name", "")
        if not _EXPECTED_USER or not _EXPECTED_GROUP:
             _EVALUATOR.logger.warning("Handler: 任务参数 'user_to_add' 或 'group_name' 未在配置中找到！")
    else:
        _EVALUATOR.logger.error("Handler: 评估器配置未加载，无法运行任务。")
        _CONFIG = {} # 避免 None 引用

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理来自 Frida 的消息。
    记录 AgentEvents 到 ResultCollector。
    返回 "success" 或 "error" 字符串给 BaseEvaluator 以触发回调。
    """
    global _EVALUATOR, _CONFIG, _EXPECTED_USER, _EXPECTED_GROUP

    if _EVALUATOR is None:
        print("严重警告: 评估器未设置，无法处理消息！")
        return "error" # 如果评估器未设置，应视为错误

    msg_type = message.get('type')
    payload = message.get('payload')
    current_time = time.time() # 获取当前时间以便记录事件

    # 处理来自 Frida 脚本的 'send' 类型消息
    if msg_type == 'send' and isinstance(payload, dict) and 'event' in payload:
        script_event_name = payload['event']
        _EVALUATOR.logger.debug(f"Handler: 接收到脚本事件: {script_event_name}, Payload: {payload}")

        # 记录通用的 APP_SPECIFIC_EVENT，包含原始 payload
        # 这是为了保留所有从脚本收到的原始信息
        _EVALUATOR.record_event(
            AgentEvent.APP_SPECIFIC_EVENT,
            {'timestamp': current_time, 'name': script_event_name, 'payload': payload}
        )

        # --- 根据脚本事件类型执行特定逻辑 --- #

        if script_event_name == "script_initialized":
            _EVALUATOR.logger.info(f"Handler: 钩子脚本初始化: {payload.get('message', '')}")
            # 无需记录特定指标事件

        elif script_event_name == "function_found":
            _EVALUATOR.logger.info(f"Handler: 找到函数地址: {payload.get('address', '')}")
            # 无需记录特定指标事件
            # 移除: _EVALUATOR.update_metric("found_function", True)

        elif script_event_name == "apply_chat_update_called":
            _EVALUATOR.logger.info("Handler: 拦截到本地群组状态更新函数调用")
            # 无需记录特定指标事件

        elif script_event_name == "participants_count":
            count = payload.get("count", 0)
            _EVALUATOR.logger.info(f"Handler: 群组当前有 {count} 个成员")
            # 无需记录特定指标事件

        elif script_event_name == "chatinfo_updated":
            chat_name = payload.get("chat_name", "")
            participants = payload.get("participants", [])
            _EVALUATOR.logger.info(f"Handler: 收到群组更新 - 名称: '{chat_name}', 成员: {participants}")

            # 检查是否是目标群组
            if chat_name.lower() == _EXPECTED_GROUP.lower():
                step1_name = "找到目标群组"
                _EVALUATOR.logger.info(f"Handler: 匹配到目标群组: '{chat_name}'")
                # 记录关键步骤 1 完成
                _EVALUATOR.record_event(AgentEvent.KEY_STEP_COMPLETED, {
                    'timestamp': current_time,
                    'step_index': 1,
                    'step_name': step1_name # 提供步骤名称给 Metric
                })
                # 移除: _EVALUATOR.update_metric("group_found", True)

                # 检查目标用户是否在成员列表中
                user_found = any(p.lower() == _EXPECTED_USER.lower() for p in participants)
                if user_found:
                    step2_name = "确认用户已添加"
                    success_message = f"目标用户 '{_EXPECTED_USER}' 已成功添加到群组 '{chat_name}'"
                    _EVALUATOR.logger.info(f"Handler: {success_message}")

                    # 记录关键步骤 2 完成
                    _EVALUATOR.record_event(AgentEvent.KEY_STEP_COMPLETED, {
                        'timestamp': current_time,
                        'step_index': 2,
                        'step_name': step2_name
                    })
                    # 移除: _EVALUATOR.update_metric("user_found", True)
                    # 移除: _EVALUATOR.update_metric("success", True)
                    # 移除: 时间计算和 time_to_complete

                    # 记录任务成功结束事件
                    _EVALUATOR.record_event(AgentEvent.TASK_END, {
                        'timestamp': current_time,
                        'status': 'success',
                        'reason': success_message
                    })

                    # 返回 "success" 字符串给 BaseEvaluator 以触发回调
                    return "success"
                else:
                     _EVALUATOR.logger.info(f"Handler: 目标用户 '{_EXPECTED_USER}' 尚未在群组 '{chat_name}' 成员列表中。")
            else:
                _EVALUATOR.logger.debug(f"Handler: 收到的群组 '{chat_name}' 不是目标群组 '{_EXPECTED_GROUP}'。")

        elif script_event_name == "error": # 来自应用的错误事件
            error_type = payload.get("error_type", "script_error")
            message = payload.get("message", "未知脚本错误")
            error_reason = f"钩子脚本错误 ({error_type}): {message}"
            _EVALUATOR.logger.error(f"Handler: {error_reason}")

            # 记录 Agent 错误事件
            _EVALUATOR.record_event(AgentEvent.AGENT_ERROR_OCCURRED, {
                'timestamp': current_time,
                'error': error_type,
                'message': message
                # 'stack_trace': payload.get('stack') # 如果脚本能提供堆栈信息
            })
            # 移除: _EVALUATOR.update_metric("error", ...)

            # 记录任务失败结束事件
            _EVALUATOR.record_event(AgentEvent.TASK_END, {
                'timestamp': current_time,
                'status': 'failure',
                'reason': error_reason
            })

            # 返回 "error" 字符串给 BaseEvaluator
            return "error"

    # 处理来自 Frida 的 'error' 类型消息 (通常是 JS 语法错误等)
    elif msg_type == 'error':
        stack_trace = message.get('stack', '')
        error_description = message.get('description', '未知 Frida 错误')
        error_reason = f"Frida JS 错误: {error_description}"
        _EVALUATOR.logger.error(f"Handler: {error_reason}\nStack: {stack_trace}")

        # 记录 Agent 错误事件
        _EVALUATOR.record_event(AgentEvent.AGENT_ERROR_OCCURRED, {
            'timestamp': current_time,
            'error': 'Frida Error',
            'message': error_description,
            'stack_trace': stack_trace
        })

        # 记录任务失败结束事件
        _EVALUATOR.record_event(AgentEvent.TASK_END, {
            'timestamp': current_time,
            'status': 'failure',
            'reason': error_reason
        })

        # 返回 "error" 字符串给 BaseEvaluator
        return "error"

    # 如果没有明确返回 "success" 或 "error"，则返回 None 表示任务仍在进行中
    return None

def register_handlers(evaluator):
    """注册消息处理器并设置评估器实例"""
    set_evaluator(evaluator)
    return message_handler
