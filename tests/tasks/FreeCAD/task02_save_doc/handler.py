#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD事件处理器
负责处理钩子脚本产生的事件并判断任务是否完成
"""

import os
from typing import Dict, Any, Optional, List

# 事件类型常量
SCRIPT_INITIALIZED = "script_initialized"
FUNCTION_NOT_FOUND = "function_not_found"
FUNCTION_FOUND = "function_found"
FUNCTION_CALLED = "function_called"
FUNCTION_KEY_WORD_DETECTED = "funtion_key_word_detected"
ERROR = "error"
HOOK_INSTALLED = "hook_installed"

# 关键字相关常量
SOURCE_PATH = "source_path"
KEY = "filename"
KEY_WORDS = [KEY, SOURCE_PATH]

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: Frida消息对象
        logger: 日志记录器
        task_parameter: 任务参数
        
    Returns:
        List[Dict[str, Any]]: 包含状态更新的字典列表，如果没有状态更新则返回None
    """
    # 处理消息
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        # 检查是否包含事件类型
        if 'event' in payload:
            event_type = payload['event']
            logger.debug(f"接收到事件: {event_type}")
            
            # 处理特定事件
            if event_type == SCRIPT_INITIALIZED:
                logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                return None
                
            elif event_type == FUNCTION_FOUND:
                logger.info(f"找到函数: {payload.get('address', '')}")
                return None
                
            elif event_type == FUNCTION_CALLED: 
                logger.info(f"函数被调用: {payload.get('message', '')}")
                return None
                
            elif event_type == FUNCTION_KEY_WORD_DETECTED:
                log_info = f"函数检测到关键字: {payload.get('message', '')}"
                for key in KEY_WORDS:
                    if key in payload:
                        log_info += f", {key}: {{{payload.get(key, '')}}}"
                logger.info(log_info)

                source_path = task_parameter.get(SOURCE_PATH, '')
                expected_key = source_path + task_parameter.get(KEY, '')
                key = payload.get(KEY, '')
                logger.debug(f"预期关键字: {expected_key}, 实际关键字: {key}")

                if key == expected_key and os.path.exists(expected_key):
                    # 创建状态更新列表
                    updates = []
                    
                    # 报告关键步骤已完成
                    updates.append({
                        'status': 'key_step',
                        'index': 1,
                        'name': '成功保存文档'
                    })
                    
                    # 报告任务成功
                    updates.append({
                        'status': 'success',
                        'reason': '成功保存了文档到指定路径'
                    })
                    
                    logger.info(f"任务成功完成!")
                    return updates
                
            elif event_type == ERROR:
                error_type = payload.get("error_type", "unknown")
                error_message = payload.get("message", "未知错误")
                
                logger.error(f"钩子脚本错误 ({error_type}): {error_message}")
                
                return [{
                    'status': 'error',
                    'type': error_type,
                    'message': error_message
                }]
                
    elif message.get('type') == 'error':
        logger.error(f"钩子脚本错误: {message.get('stack', '')}")
        
        return [{
            'status': 'error',
            'type': 'script_error',
            'message': message.get('stack', '未知错误')
        }]
    
    return None