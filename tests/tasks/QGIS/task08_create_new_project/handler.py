#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
QGIS创建新项目事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: Frida消息对象
        logger: 日志记录器
        task_parameter: 任务参数
        
    Returns:
        Optional[List[Dict[str, Any]]]: 如果任务状态有更新返回状态列表，否则返回None
    """

    # 处理消息
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        # 检查是否包含事件类型
        if 'event' in payload:
            event_type = payload['event']
            logger.debug(f"接收到事件: {event_type}")
            
            # 处理特定事件
            if event_type == "script_initialized":
                logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                return None
                
            elif event_type == "clear_function_found":
                logger.info(f"找到创建新项目函数: {payload.get('address', '')}")
                return None
                
            elif event_type == "setPath_function_found":
                logger.info(f"找到保存项目函数: {payload.get('address', '')}")
                return None
                
            elif event_type == "newProject_created":
                logger.info(f"检测到创建新项目")
                
                # 返回关键步骤
                return [{"status": "key_step", "index": 1, "name": "创建新项目成功"}]
                
            elif event_type == "newProject_saved":
                path = payload.get("path", "")
                logger.info(f"检测到保存项目: 路径={path}")
                
                # 检查路径是否匹配预期
                expected_path = task_parameter.get("save_path", "").lower()
                
                path_matches = expected_path in path.lower() or os.path.basename(expected_path) in path.lower()
                
                if path_matches:
                    logger.info("保存路径匹配预期目标!")                    
                    # 返回关键步骤和成功状态（全部步骤完成）
                    return [
                        {"status": "key_step", "index": 2, "name": "保存新项目成功"},
                        {"status": "success", "reason": f"成功创建并保存新项目: 路径={path}"}
                    ]
                else:
                    logger.info(f"保存路径与预期不符。预期路径: {expected_path}, 实际: {path}")
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                error_message = payload.get("message", "未知错误")
                logger.error(f"钩子脚本错误 ({error_type}): {error_message}")
                
                # 返回错误状态
                return [{
                    "status": "error",
                    "type": error_type,
                    "message": error_message
                }]
                
    elif message.get('type') == 'error':
        stack = message.get('stack', '')
        logger.error(f"钩子脚本错误: {stack}")
        
        # 返回错误状态
        return [{
            "status": "error",
            "type": "script_error",
            "message": "钩子脚本执行错误",
            "stack_trace": stack
        }]
    
    return None
