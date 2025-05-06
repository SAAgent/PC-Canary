#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
from typing import Dict, Any, Optional, List

_EVENT_FUNCTION_RETURN = "function returned"

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    payload = message['payload']
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    key_step = []
    if event_type == _EVENT_FUNCTION_RETURN:           
        function = payload.get('function', '')
        logger.info("函数返回: " + function)
        if function == "OBSBasic::Save":
            file = payload.get("file", "")
            logger.info("场景文件: " + file)
            if file and os.path.exists(file):
                with open(file, 'r') as f:
                    scene_data = json.load(f)
                    sources = scene_data.get('sources', [])
                    scene_name = task_parameter.get("scene_name", "")
                    # 检查场景名称是否存在
                    if scene_name:
                        for source in sources:
                            if source.get('name') == scene_name:
                                key_step.append({"status": "key_step", "index": 1})
                                logger.info("key step 1: 场景文件中存在场景")
                                # 检查场景中的settings字典的items列表里是否存在文本源名称
                                items = source.get('settings', {}).get('items', [])
                                for item in items:
                                    if item.get('name') == task_parameter.get("new_source_name", ""):
                                        key_step.append({"status": "key_step", "index": 2})
                                        logger.info("key step 2: 场景文件中存在文本源")
                                        break
                                else:
                                    logger.error(f"场景 {scene_name} 中不存在文本源")
                                    key_step.append({"status": "error", "message": f"场景 {scene_name} 中不存在文本源"})
                                break
                        else:
                            logger.error(f"场景 {scene_name} 不存在")
                            key_step.append({"status": "error", "message": f"场景 {scene_name} 不存在"})
                    else:
                        logger.error("场景名称未提供")
                        key_step.append({"status": "error", "message": "场景名称未提供"})
                    # 检查文本源名称是否存在
                    name = task_parameter.get("new_source_name", "")
                    for source in sources:
                        if source.get('name') == name:
                            source_settings = source.get('settings', {})
                            expected_settings = task_parameter.get("settings", {})
                            # 检查expected_settings中的所有设置是否都在source_settings中，并且值完全匹配
                            is_match = True
                            for key, expected_value in expected_settings.items():
                                if key not in source_settings:
                                    is_match = False
                                    logger.error(f"设置项 {key} 不存在")
                                    break
                                if source_settings[key] != expected_value:
                                    is_match = False
                                    logger.error(f"设置项 {key} 的值不匹配: 期望 {expected_value}, 实际 {source_settings[key]}")
                                    break
                                    
                            if is_match:
                                key_step.append({"status": "key_step", "index": 3})
                                logger.info("key step 3: 场景文件中设置匹配")
                                key_step.append({"status": "success", "reason": "场景和文本源匹配，设置成功"})
                                logger.info(f"文本源 {name} 的设置匹配成功")
                            else:
                                logger.error(f"文本源 {name} 的设置不匹配")
                                logger.debug(f"期望设置: {expected_settings}")
                                logger.debug(f"实际设置: {source_settings}")

    return key_step
