#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
QGIS配置项目Crs事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

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
                
            elif event_type == "setCrs_function_found":
                logger.info(f"找到setCrs函数: {payload.get('address', '')}")
                return None
                
            elif event_type == "newCrs_detected":
                detected_crs = payload.get("crs", "")
                logger.info(f"检测到CRS变更: {detected_crs}")
                
                # 检查CRS是否匹配预期
                expected_crs = task_parameter.get("crs", "2964")
                
                # 判断检测到的CRS是否与预期相符
                if str(expected_crs) == str(detected_crs):
                    logger.info("CRS匹配预期目标!")                    
                    # 返回关键步骤和成功状态
                    return [
                        {"status": "key_step", "index": 1, "name": "CRS已成功设置"},
                        {"status": "success", "reason": f"成功将坐标参考系统设置为{detected_crs}"}
                    ]
                
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
