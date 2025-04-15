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

_EVALUATOR = None
_CONFIG = None
_START_TIME = None

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator
    
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(current_dir, "config.json")
        
        with open(config_file, 'r') as f:
            _CONFIG = json.load(f)
    except Exception as e:
        if _EVALUATOR:
            _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    global _EVALUATOR, _CONFIG, _START_TIME
    
    if _START_TIME is None:
        _START_TIME = time.time()
    
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None
    
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        if 'event' in payload:
            event_type = payload['event']
            _EVALUATOR.logger.debug(f"接收到事件: {event_type}")
            
            _EVALUATOR.record_event(event_type, payload)
            
            if event_type == "script_initialized":
                _EVALUATOR.logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == "function_found":
                _EVALUATOR.logger.info(f"找到函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_function", True)
                
            elif event_type == "apply_chat_update_called":
                _EVALUATOR.logger.info("拦截到本地群组状态更新函数调用")
                
            elif event_type == "participants_count":
                count = payload.get("count", 0)
                _EVALUATOR.logger.info(f"群组当前有 {count} 个成员")
                
            elif event_type == "chatinfo_updated":
                # 获取预期的目标用户和群组
                expected_user = _CONFIG.get("expected_params", {}).get("target_user", "")
                expected_group = _CONFIG.get("expected_params", {}).get("target_group", "")
                
                chat_name = payload.get("chat_name", "")
                participants = payload.get("participants", [])
                
                _EVALUATOR.logger.info(f"群组名称: {chat_name}, 成员: {', '.join(participants)}")
                
                # 检查群组名称是否匹配
                if chat_name.lower() == expected_group.lower():
                    _EVALUATOR.logger.info(f"找到目标群组: {chat_name}")
                    _EVALUATOR.update_metric("group_found", True)
                    
                    # 检查目标用户是否在成员列表中
                    if any(participant.lower() == expected_user.lower() for participant in participants):
                        _EVALUATOR.logger.info(f"目标用户 {expected_user} 已添加到群组 {chat_name}")
                        _EVALUATOR.update_metric("user_found", True)
                        
                        # 标记任务成功并计算完成时间
                        _EVALUATOR.update_metric("success", True)
                        completion_time = time.time() - _START_TIME
                        _EVALUATOR.update_metric("time_to_complete", completion_time)
                        _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
                        return "success"
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
                
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    
    return None

def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler