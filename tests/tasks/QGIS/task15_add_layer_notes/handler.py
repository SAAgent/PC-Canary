#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
QGIS添加图层注解事件处理器
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
                
            elif event_type == "set_function_found":
                logger.info(f"找到添加图层注解函数: {payload.get('address', '')}")
                return None
                
            elif event_type == "layer_set":
                layer_name = payload.get("name", "")
                logger.info(f"检测到添加图层注解: {layer_name}")
                
                # 检查图层名称是否匹配预期
                expected_layer_name = task_parameter.get("LayerName", "")
                logger.debug(f"比较图层名称 - 检测到: {layer_name}, 预期: {expected_layer_name}")
                
                # 判断检测到的图层名称是否与预期相符
                if expected_layer_name.lower() in layer_name.lower():
                    logger.info("添加注解的图层名称匹配预期目标!")                    
                    # 返回关键步骤
                    return [{"status": "key_step", "index": 1, "name": "正在操作预期图层"}]
                else:
                    logger.info(f"添加注解的图层名称与预期不符。预期: {expected_layer_name}, 实际: {layer_name}")
                
            elif event_type == "notes_set":
                layer_name = payload.get("layer", "")
                notes_text = payload.get("notes", "")
                notes_html = payload.get("notes_html", "")
                
                logger.info(f"检测到为图层 {layer_name} 添加注解: {notes_text}")
                
                # 检查图层名称和注解内容是否匹配预期
                expected_layer_name = task_parameter.get("LayerName", "")
                expected_notes = task_parameter.get("notes", "")
                
                # 清理和比较注解内容
                detected_notes = notes_text.strip().lower()
                expected_notes = expected_notes.strip().lower()
                
                # 判断检测到的注解内容是否与预期相符
                layer_match = expected_layer_name.lower() in layer_name.lower()
                notes_match = expected_notes in detected_notes
                
                if layer_match and notes_match:
                    logger.info(f"添加的图层注解匹配预期! 图层: {layer_name}, 注解: {notes_text}")                    
                    # 返回关键步骤和成功状态
                    return [
                        {"status": "key_step", "index": 2, "name": "设置了预期标注"},
                        {"status": "success", "reason": f"成功为图层 {layer_name} 添加注解: {notes_text}"}
                    ]
                else:
                    if not layer_match:
                        logger.info(f"图层与预期不符。预期: {expected_layer_name}, 实际: {layer_name}")
                    if not notes_match:
                        logger.info(f"注解内容与预期不符。预期: {expected_notes}, 实际: {detected_notes}")
                
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
