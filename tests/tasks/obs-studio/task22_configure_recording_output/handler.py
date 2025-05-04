#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OBS Studio配置录制输出路径与格式并测试录制任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional

_EVALUATOR = None
_CONFIG = None
_START_TIME = None


def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator

    # 使用评估器的已更新配置，而不是重新读取文件
    if hasattr(evaluator, "config") and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("使用评估器中的更新配置")
    else:
        # 作为备份，如果评估器中没有配置，才从文件读取
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "config.json")

            with open(config_file, "r") as f:
                _CONFIG = json.load(f)
                _EVALUATOR.logger.info("从文件加载配置")
        except Exception as e:
            if _EVALUATOR:
                _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")
            # 提供一个默认配置以避免空引用
            _CONFIG = {
                "task_id": "22", 
                "task_name": "configure_recording_output",
                "description": "配置录制输出路径与格式并测试录制",
                "task_parameters": {
                    "output_path": "/tmp/obs-recordings",
                    "output_format": "mp4"
                }
            }


def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: injector消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _EVALUATOR, _CONFIG, _START_TIME
    
    if _START_TIME is None:
        _START_TIME = time.time()
    
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None
    
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        if 'event' in payload:
            event_type = payload['event']
            _EVALUATOR.logger.debug(f"接收到事件: {event_type}")
            
            _EVALUATOR.record_event(event_type, payload)
            
            if event_type == "script_initialized":
                _EVALUATOR.logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == "function_found":
                _EVALUATOR.logger.info(f"找到函数: {payload.get('address', '')}")
                _EVALUATOR.update_metric("found_function", True)
                
            elif event_type == "config_file_found":
                config_file_path = payload.get("path", "")
                _EVALUATOR.logger.info(f"找到配置文件路径: {config_file_path}")
                
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
                    
                    # 检查RecFormat2值
                    if rec_format2_value is not None:
                        _EVALUATOR.logger.info(f"在配置文件中找到RecFormat2值: {rec_format2_value}")
                        expected_format = _CONFIG.get("task_parameters", {}).get("output_format", "")
                        
                        if rec_format2_value == expected_format:
                            _EVALUATOR.update_metric("output_format_configured", True)
                            _EVALUATOR.logger.info(f"录制输出格式已正确配置为: {rec_format2_value}")
                        else:
                            _EVALUATOR.logger.warning(f"录制输出格式配置不匹配，期望: {expected_format}，实际: {rec_format2_value}")
                    else:
                        _EVALUATOR.logger.warning("在配置文件中未找到RecFormat2设置")
                    
                    # 检查FilePath值
                    if file_path_value is not None:
                        _EVALUATOR.logger.info(f"在配置文件中找到FilePath值: {file_path_value}")
                        expected_path = _CONFIG.get("task_parameters", {}).get("output_path", "")
                        
                        if expected_path in file_path_value:
                            _EVALUATOR.update_metric("output_path_configured", True)
                            _EVALUATOR.logger.info(f"录制输出路径已正确配置为: {file_path_value}")
                        else:
                            _EVALUATOR.logger.warning(f"录制输出路径配置不匹配，期望: {expected_path}，实际: {file_path_value}")
                    else:
                        _EVALUATOR.logger.warning("在配置文件中未找到FilePath设置")
                    
                except Exception as e:
                    _EVALUATOR.logger.error(f"读取或解析配置文件失败: {str(e)}")
                
            elif event_type == "output_path_configured":
                # 保留这个事件处理，以防直接从API获取路径
                _EVALUATOR.logger.info("通过API获取到录制输出路径")
                configured_path = payload.get("path", "")
                expected_path = _CONFIG.get("task_parameters", {}).get("output_path", "")
                
                if expected_path in configured_path:
                    _EVALUATOR.update_metric("output_path_configured", True)
                    _EVALUATOR.logger.info(f"录制输出路径已正确配置为: {configured_path}")
                else:
                    _EVALUATOR.logger.warning(f"录制输出路径配置不匹配，期望: {expected_path}，实际: {configured_path}")
                
            elif event_type == "output_format_configured":
                # 保留这个事件处理，以防直接从API获取格式
                _EVALUATOR.logger.info("通过API获取到录制输出格式")
                configured_format = payload.get("format", "")
                expected_format = _CONFIG.get("task_parameters", {}).get("output_format", "")
                
                if configured_format == expected_format:
                    _EVALUATOR.update_metric("output_format_configured", True)
                    _EVALUATOR.logger.info(f"录制输出格式已正确配置为: {configured_format}")
                else:
                    _EVALUATOR.logger.warning(f"录制输出格式配置不匹配，期望: {expected_format}，实际: {configured_format}")
                
            elif event_type == "save_output_settings_called":
                _EVALUATOR.logger.info("拦截到保存输出设置函数调用")
                
            elif event_type == "save_output_settings_returned":
                _EVALUATOR.logger.info("保存输出设置函数返回")
                
            elif event_type == "start_recording_called":
                _EVALUATOR.logger.info("拦截到开始录制函数调用")
                _EVALUATOR.update_metric("start_recording_called", True)
                
            elif event_type == "stop_recording_called":
                _EVALUATOR.logger.info("拦截到停止录制函数调用")
                _EVALUATOR.update_metric("stop_recording_called", True)
                
                # 如果开始录制和停止录制都被调用，则认为录制功能已测试
                if _EVALUATOR.get_metric("start_recording_called"):
                    _EVALUATOR.update_metric("recording_tested", True)
                    _EVALUATOR.logger.info("录制功能已成功测试")
                    
                    # 检查所有成功条件是否都满足
                    if (_EVALUATOR.get_metric("output_path_configured") and 
                        _EVALUATOR.get_metric("output_format_configured") and 
                        _EVALUATOR.get_metric("recording_tested")):
                        
                        # 标记任务成功并计算完成时间
                        _EVALUATOR.update_metric("success", True)
                        completion_time = time.time() - _START_TIME
                        _EVALUATOR.update_metric("time_to_complete", completion_time)
                        _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
                        return "success"
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
                
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    
    return None


def register_handlers(evaluator):
    """
    注册所有事件处理函数到评估器
    
    Args:
        evaluator: 评估器实例
        
    Returns:
        message_handler: 处理函数
    """
    set_evaluator(evaluator)
    return message_handler
