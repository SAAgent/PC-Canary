#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
QGIS调整图层次序事件处理器
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
                
            elif event_type == "setOrder_function_found":
                logger.info(f"找到设置图层次序函数: {payload.get('address', '')}")
                return None
                
            elif event_type == "order_set":
                layer_names = payload.get("layer_names", [])
                order_string = payload.get("order_string", "")
                count = payload.get("layer_count", 0)
                
                logger.info(f"检测到图层次序变更: 共{count}个图层, 顺序为: {order_string}")
                
                # 检查图层次序是否匹配预期
                expected_order = task_parameter.get("LayerOrder", "").strip()
                expected_layers = [layer.strip() for layer in expected_order.split(",")]
                
                logger.debug(f"比较图层次序 - 检测到: {layer_names}, 预期: {expected_layers}")
                
                # 判断检测到的图层次序是否与预期相符
                # 这里只比较图层名称是否包含预期名称，顺序也必须一致
                match = True
                if len(layer_names) >= len(expected_layers):
                    for i, expected_layer in enumerate(expected_layers):
                        found = False
                        for actual_layer in layer_names:
                            if expected_layer.lower() in actual_layer.lower():
                                found = True
                                # 确保顺序一致
                                if layer_names.index(actual_layer) != i:
                                    logger.info(f"图层 {expected_layer} 顺序不匹配")
                                    match = False
                                break
                        if not found:
                            logger.info(f"未找到预期图层: {expected_layer}")
                            match = False
                else:
                    logger.info(f"图层数量不匹配。预期: 至少{len(expected_layers)}层, 实际: {len(layer_names)}层")
                    match = False
                
                if match:
                    logger.info("图层次序匹配预期目标!")                    
                    # 返回关键步骤和成功状态
                    return [
                        {"status": "key_step", "index": 1, "name": "预期图层次序已设置"},
                        {"status": "success", "reason": f"成功设置图层次序: {order_string}"}
                    ]
                else:
                    logger.info(f"图层次序与预期不符。预期: {expected_order}, 实际: {order_string}")
                
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
