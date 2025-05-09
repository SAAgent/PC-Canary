#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OBS Studio配置录制输出路径与格式并测试录制任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, List

key_steps = []

start_recording = False

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global key_steps, start_recording
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    if event_type == "config_file_found":
        config_file_path = payload.get("path", "")
        logger.info(f"找到配置文件路径: {config_file_path}")
        
        # 等待一段时间以确保文件已经被写入
        time.sleep(1)
        
        # 读取配置文件内容
        try:
            with open(config_file_path, "r") as f:
                config_content = f.read()
            
            # 解析配置文件内容，查找[SimpleOutput]节中的RecFormat2的值
            lines = config_content.split('\n')
            in_simple_output_section = False
            rec_format2_value = None
            file_path_value = None
            
            for line in lines:
                trimmed_line = line.strip()
                
                if trimmed_line == '[SimpleOutput]':
                    in_simple_output_section = True
                    continue
                
                if in_simple_output_section and trimmed_line.startswith('['):
                    # 已经离开[SimpleOutput]节
                    break
                
                if in_simple_output_section and trimmed_line.startswith('RecFormat2='):
                    rec_format2_value = trimmed_line[len('RecFormat2='):]
                
                if in_simple_output_section and trimmed_line.startswith('FilePath='):
                    file_path_value = trimmed_line[len('FilePath='):]
            
            # 检查FilePath值
            if file_path_value is not None:
                logger.info(f"在配置文件中找到FilePath值: {file_path_value}")
                expected_path = task_parameter.get("output_path", "")
                
                if expected_path in file_path_value:
                    key_steps.append({"status":"key_step","index":1})
                    logger.info(f"录制输出路径已正确配置为: {file_path_value}")
                else:
                    logger.warning(f"录制输出路径配置不匹配，期望: {expected_path}，实际: {file_path_value}")
            else:
                logger.warning("在配置文件中未找到FilePath设置")
            
            # 检查RecFormat2值
            if rec_format2_value is not None:
                logger.info(f"在配置文件中找到RecFormat2值: {rec_format2_value}")
                expected_format = task_parameter.get("output_format", "")
                
                if rec_format2_value == expected_format:
                    key_steps.append({"status":"key_step","index":2})
                    logger.info(f"录制输出格式已正确配置为: {rec_format2_value}")
                else:
                    logger.warning(f"录制输出格式配置不匹配，期望: {expected_format}，实际: {rec_format2_value}")
            else:
                logger.warning("在配置文件中未找到RecFormat2设置")
            
        except Exception as e:
            logger.error(f"读取或解析配置文件失败: {str(e)}")

        return key_steps
        
    elif event_type == "output_path_configured":
        # 保留这个事件处理，以防直接从API获取路径
        logger.info("通过API获取到录制输出路径")
        configured_path = payload.get("path", "")
        expected_path = task_parameter.get("output_path", "")
        
        if expected_path in configured_path:
            logger.info(f"录制输出路径已正确配置为: {configured_path}")
            if not dict_have_index(key_steps, 1):
                key_steps.append({"status":"key_step","index":1})
        else:
            logger.warning(f"录制输出路径配置不匹配，期望: {expected_path}，实际: {configured_path}")
        
        return key_steps
        
    elif event_type == "output_format_configured":
        # 保留这个事件处理，以防直接从API获取格式
        logger.info("通过API获取到录制输出格式")
        configured_format = payload.get("format", "")
        expected_format = task_parameter.get("output_format", "")
        
        if configured_format == expected_format:
            if not dict_have_index(key_steps, 2):
                key_steps.append({"status":"key_step","index":2})
            logger.info(f"录制输出格式已正确配置为: {configured_format}")
        else:
            logger.warning(f"录制输出格式配置不匹配，期望: {expected_format}，实际: {configured_format}")
        
        return key_steps

    elif event_type == "start_recording_called":
        start_recording = True
        logger.info("录制开始")

    elif event_type == "stop_recording_called":
        # 如果开始录制和停止录制都被调用，则认为录制功能已测试
        if start_recording:
            if not dict_have_index(key_steps, 3):
                key_steps.append({"status":"key_step","index":3})
            logger.info("录制功能已成功测试")
            print(key_steps)
            # 检查所有成功条件是否都满足
            if len(key_steps) == 3:
                key_steps.append({"status":"success", "reason": "输出路径和输出格式都匹配，并且录制测试完成"})
                return key_steps
    
    return None

def dict_have_index(key_steps: Dict[str, Any], index: int) -> bool:
    for key_step in key_steps:
        if "index" in key_step and key_step["index"] == index:
            return True
    
    return False
