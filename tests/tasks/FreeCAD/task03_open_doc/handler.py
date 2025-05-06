#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
from typing import Dict, Any, Optional, List

# 常量定义
FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected"
SOURCE_PATH = "source_path"
KEY = "filename"

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理从钩子脚本接收的消息

    Args:
        message: Frida消息对象
        logger: 记录日志的logger对象
        task_parameter: 任务参数

    Returns:
        Optional[List[Dict[str, Any]]]: 状态字典列表或None
    """
    # 处理消息
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        # 检查是否包含事件类型
        if 'event' in payload:
            event_type = payload['event']
            logger.debug(f"接收到事件: {event_type}")
            
            # 返回的状态更新列表
            updates = []
            
            # 处理特定事件
            if event_type == "script_initialized":
                logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == "function_found":
                logger.info(f"找到函数: {payload.get('address', '')}")
                # 不再将其标记为关键步骤
                
            elif event_type == "function_called": 
                logger.info(f"函数被调用: {payload.get('message', '')}")
                # 不再将其标记为关键步骤
                
            elif event_type == FUNCTION_KEY_WORD_DETECTED:
                log_info = f"函数检测到关键字: {payload.get('message', '')}"
                logger.info(log_info)

                source_path = task_parameter.get(SOURCE_PATH, '')
                expected_key = source_path + task_parameter.get(KEY, '')
                key = payload.get('filename', '')
                logger.debug(f"预期关键字: {expected_key}, 实际关键字: {key}")

                if key and os.path.exists(expected_key):
                    # 这是唯一的关键步骤
                    updates.append({
                        'status': 'key_step',
                        'index': 1,
                    })
                    
                    # 标记任务成功
                    updates.append({
                        'status': 'success',
                        'reason': f"成功打开文档: {key}"
                    })
                    
                    logger.info(f"任务成功完成！文档已打开: {key}")
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                error_message = payload.get("message", "未知错误")
                
                logger.error(f"钩子脚本错误 ({error_type}): {error_message}")
                
                # 报告错误
                updates.append({
                    'status': 'error',
                    'type': error_type,
                    'message': error_message
                })
            
            # 如果有状态更新，返回它们
            if updates:
                return updates
                
    elif message.get('type') == 'error':
        logger.error(f"钩子脚本错误: {message.get('stack', '')}")
        return [{
            'status': 'error',
            'type': 'script_error',
            'message': f"钩子脚本错误: {message.get('description', '未知错误')}", 
            'stack_trace': message.get('stack', '')
        }]
    
    return None