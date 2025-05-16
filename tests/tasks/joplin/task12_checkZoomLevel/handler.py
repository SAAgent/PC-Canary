#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin检查视图缩放比例的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    # 打印完整的参数信息
    logger.info("="*50)
    logger.info("参数调试信息:")
    logger.info(f"message 类型: {type(message)}")
    logger.info(f"message 内容: {message}")
    logger.info(f"message.get('data') 类型: {type(message.get('data'))}")
    logger.info(f"message.get('data') 内容: {message.get('data')}")
    logger.info(f"task_parameter 类型: {type(task_parameter)}")
    logger.info(f"task_parameter 内容: {task_parameter}")
    logger.info("="*50)
    
    if event_type == "evaluate_on_completion":
        try:
            # 获取当前缩放比例
            data = message.get("data")
            logger.info(f"data 类型: {type(data)}")
            logger.info(f"data 内容: {data}")
            
            current_zoom = float(data) if data is not None else 1.0
            expected_zoom = float(task_parameter.get('zoom_level', 1.0))
            
            logger.info(f"正在检测缩放比例是否为: {expected_zoom}")
            logger.info(f"当前Joplin缩放比例为: {current_zoom}")
            
            # 允许0.01的误差范围
            if abs(current_zoom - expected_zoom) < 0.01:
                return [
                    {"status": "key_step", "index": 1},
                    {"status": "success", "reason": f"视图缩放比例已经成功设置为{expected_zoom}"}
                ]
            else:
                return [{"status": "error", "type": "evaluate_on_completion", "message": f"缩放比例不匹配，期望：{expected_zoom}，实际：{current_zoom}"}]
        except (TypeError, ValueError) as e:
            logger.error(f"数据类型转换错误: {str(e)}")
            logger.error(f"错误详情 - data类型: {type(data)}, data值: {data}")
            return [{"status": "error", "type": "evaluate_on_completion", "message": f"数据类型错误: {str(e)}"}]
    return None