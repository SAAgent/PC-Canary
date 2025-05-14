#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
QGIS导出地图图像事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import re
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
                
            elif event_type == "setPathandType_function_found":
                logger.info(f"找到设置导出路径和类型函数: {payload.get('address', '')}")
                return None
                
            elif event_type == "setSize_function_found":
                logger.info(f"找到设置尺寸函数: {payload.get('address', '')}")
                return None
                
            elif event_type == "PathandType_set":
                path = payload.get("path", "")
                file_type = payload.get("type", "")
                logger.info(f"检测到导出图片设置: 路径={path}, 类型={file_type}")
                
                # 检查路径是否匹配预期
                expected_path = task_parameter.get("save_path", "").lower()
                expected_type = task_parameter.get("type", "").lower()
                
                path_matches = expected_path in path.lower() or os.path.basename(expected_path) in path.lower()
                
                # 类型可能包含在过滤器字符串中，如"PNG Files (*.png)"
                type_matches = expected_type in file_type.lower()
                
                if path_matches and type_matches:
                    logger.info("导出路径和类型匹配预期目标!")                    
                    # 返回关键步骤
                    return [{"status": "key_step", "index": 1, "name": "图片路径和类型正确"}]
                else:
                    logger.info(f"导出设置与预期不符。预期路径: {expected_path}, 实际: {path}; 预期类型: {expected_type}, 实际: {file_type}")
                
            elif event_type == "Size_set":
                width = payload.get("width", 0)
                height = payload.get("height", 0)
                logger.info(f"检测到导出图片尺寸: 宽={width}px, 高={height}px")
                
                # 检查尺寸是否匹配预期
                expected_width = int(task_parameter.get("width", "0"))
                expected_height = int(task_parameter.get("height", "0"))
                
                if width == expected_width and height == expected_height:
                    logger.info("导出尺寸匹配预期目标!")                    
                    # 返回关键步骤和成功状态（全部步骤完成）
                    return [
                        {"status": "key_step", "index": 2, "name": "图片尺寸正确"},
                        {"status": "success", "reason": f"成功导出地图图像: 路径匹配, 尺寸={width}x{height}"}
                    ]
                else:
                    logger.info(f"导出尺寸与预期不符。预期: {expected_width}x{expected_height}, 实际: {width}x{height}")
                
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
