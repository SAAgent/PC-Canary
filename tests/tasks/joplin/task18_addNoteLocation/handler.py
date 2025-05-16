#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
joplin添加笔记位置信息的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def get_integer_part(value: str) -> int:
    """获取数值的整数部分"""
    if value is None:
        return None
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return None

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message.get('message'))
    
    if event_type == "evaluate_on_completion":
        data = message.get("data", {})
        note_location = data.get("location", {})
        
        # 从task_parameter获取期望的位置信息
        expected_latitude = task_parameter.get('latitude')
        expected_longitude = task_parameter.get('longitude')
        
        # 获取实际的位置信息
        actual_latitude = note_location.get('latitude')
        actual_longitude = note_location.get('longitude')
        
        logger.info(f"期望的位置信息：纬度 {expected_latitude}，经度 {expected_longitude}")
        logger.info(f"实际的位置信息：纬度 {actual_latitude}，经度 {actual_longitude}")
        
        # 获取整数部分进行比较
        expected_lat_int = get_integer_part(expected_latitude)
        expected_lon_int = get_integer_part(expected_longitude)
        actual_lat_int = get_integer_part(actual_latitude)
        actual_lon_int = get_integer_part(actual_longitude)
        
        # 检查整数部分是否匹配
        if (expected_lat_int is not None and actual_lat_int is not None and
            expected_lon_int is not None and actual_lon_int is not None and
            expected_lat_int == actual_lat_int and 
            expected_lon_int == actual_lon_int):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"成功为笔记添加位置信息：纬度 {expected_latitude}，经度 {expected_longitude}"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", 
                    "message": f"位置信息不匹配，期望：纬度 {expected_latitude}，经度 {expected_longitude}，实际：纬度 {actual_latitude}，经度 {actual_longitude}"}]
    return None