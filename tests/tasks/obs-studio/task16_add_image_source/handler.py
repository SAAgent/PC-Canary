#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")

    # 处理图像源添加事件
    if event_type == "image_source_added":
        source_name = payload.get("source_name")
        image_path = payload.get("image_path")
        
        if (source_name == task_parameter["source_name"] and 
            image_path == task_parameter["image_path"]):
            logger.info("图像源添加成功")
            return [
                {"status": "key_step", "index": 1},
            ]

    # 处理不透明度设置事件
    elif event_type == "opacity_set":
        source_name = payload.get("source_name")
        opacity = payload.get("opacity")
        print(opacity)
        print(task_parameter["opacity"])
        print( opacity == task_parameter["opacity"])
        if (source_name == task_parameter["source_name"] and 
            opacity == task_parameter["opacity"]):
            logger.info("不透明度设置成功")
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": "不透明度设置成功"},
            ]
    
    elif event_type == "filter_added":
        source_name = payload.get("source_name")
        filter_id = payload.get("filter_id")
        opacity = payload.get("opacity")
        if (source_name == task_parameter["source_name"] and 
            filter_id == task_parameter["filter_id"] and
            opacity == task_parameter["opacity"]):
            logger.info("滤镜添加成功")
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": "滤镜添加成功"},
            ]

    return None
