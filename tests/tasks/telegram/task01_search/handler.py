#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram搜索任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, Callable

# 全局评估器实例，由message_handler使用
_EVALUATOR = None
_CONFIG = None
_START_TIME = None

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator
    
    # 加载配置
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(current_dir, "config.json")
        
        with open(config_file, 'r') as f:
            _CONFIG = json.load(f)
    except Exception as e:
        if _EVALUATOR:
            _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")
        _CONFIG = {"expected_query": "news"}

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: Frida消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _EVALUATOR, _CONFIG, _START_TIME
    
    # 初始化开始时间
    if _START_TIME is None:
        _START_TIME = time.time()
    
    # 检查评估器是否已设置
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None
    
    # 处理消息
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        # 检查是否包含事件类型
        if 'event' in payload:
            event_type = payload['event']
            _EVALUATOR.logger.debug(f"接收到事件: {event_type}")
            
            # 记录事件
            _EVALUATOR.record_event(event_type, payload)
            
            # 处理特定事件
            if event_type == "script_initialized":
                _EVALUATOR.logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == "search_function_found":
                _EVALUATOR.logger.info(f"找到搜索函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_search_function", True)
                
            elif event_type == "search_query_detected":
                query = payload.get("query", "")
                _EVALUATOR.logger.info(f"检测到搜索查询: {query}")
                
                # 检查查询是否匹配预期
                expected_query = _CONFIG.get("expected_query", "news")
                is_expected = query.lower() == expected_query.lower()
                if is_expected:
                    _EVALUATOR.logger.info("查询匹配预期目标!")
                    _EVALUATOR.update_metric("correct_query", True)
                    
            elif event_type == "target_query_found":
                query = payload.get("query", "")
                _EVALUATOR.logger.info(f"找到目标查询: {query}")
                
                # 标记任务成功并计算完成时间
                _EVALUATOR.update_metric("success", True)
                completion_time = time.time() - _START_TIME
                _EVALUATOR.update_metric("time_to_complete", completion_time)
                
                _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
                
                # 返回成功标志
                return "success"
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
                
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    
    return None

# 提供一个便捷函数来注册事件处理器
def register_handlers(evaluator):
    """
    注册所有事件处理函数到评估器
    
    Args:
        evaluator: 评估器实例
        
    Returns:
        TelegramSearchEventHandler: 事件处理器实例
    """
    # 设置全局评估器，用于message_handler
    set_evaluator(evaluator)
    
    # 回传message_handler函数
    handler = message_handler
    
    # 如果需要，可以启用单独的事件处理器注册（可选）
    # 获取配置文件中定义的事件列表
    # events = handler.config.get("events", {})
    # 
    # # 为每个事件注册处理函数
    # for event_type in events.keys():
    #     # 创建闭包来保留event_type值
    #     def create_handler(event_type):
    #         return lambda payload: handler.handle_event(event_type, payload)
    #     
    #     evaluator.register_event_handler(event_type, create_handler(event_type))
    
    return handler
