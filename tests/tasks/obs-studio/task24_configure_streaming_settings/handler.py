#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional, Callable

# 全局评估器实例，由message_handler使用
_EVALUATOR = None
_CONFIG = None
_START_TIME = None

# 任务完成状态跟踪
_TASK_STATUS = {
    "video_bitrate_set": False,
    "audio_bitrate_set": False,
    "encoder_preset_set": False,
    "replay_buffer_enabled": False,
    "replay_time_set": False
}

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG, _START_TIME
    _EVALUATOR = evaluator
    _START_TIME = time.time()
    
    # 使用评估器的已更新配置，而不是重新读取文件
    if hasattr(evaluator, 'config') and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("使用评估器中的更新配置")
    else:
        # 作为备份，如果评估器中没有配置，才从文件读取
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "config.json")
            
            with open(config_file, 'r') as f:
                _CONFIG = json.load(f)
                _EVALUATOR.logger.info("从文件加载配置")
        except Exception as e:
            if _EVALUATOR:
                _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")
            # 提供一个默认配置以避免空引用
            _CONFIG = {"task_parameters": {
                "video_bitrate": "2000",
                "audio_bitrate": "320",
                "encoder_preset": "faster",
                "replay_buffer_time": "30"
            }}

def check_task_completion():
    """检查任务是否已全部完成"""
    all_completed = all(_TASK_STATUS.values())
    
    if all_completed:
        _EVALUATOR.update_metric("success", True)
        completion_time = time.time() - _START_TIME
        _EVALUATOR.update_metric("time_to_complete", completion_time)
        _EVALUATOR.logger.info(f"任务成功完成! 耗时: {completion_time:.2f} 秒")
        return "success"
    return None

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: injector消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _EVALUATOR, _CONFIG, _TASK_STATUS
    
    # 检查评估器是否已设置
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None
    
    # 获取消息类型和有效载荷
    print(message)
    event_type = message.get("payload", {}).get("event")
    _EVALUATOR.logger.debug(f"接收到事件: {event_type}")
    
    # 处理各种事件类型
    if event_type == "video_bitrate_set":
        expected_value = int(_CONFIG["task_parameters"]["video_bitrate"])
        if message.get("payload", {}).get("value") == expected_value:
            _TASK_STATUS["video_bitrate_set"] = True
            _EVALUATOR.logger.info(f"视频比特率已正确设置为 {expected_value}Kbps")
    
    elif event_type == "audio_bitrate_set":
        expected_value = int(_CONFIG["task_parameters"]["audio_bitrate"])
        if int(message.get("payload", {}).get("value")) == expected_value:
            _TASK_STATUS["audio_bitrate_set"] = True
            _EVALUATOR.logger.info(f"音频比特率已正确设置为 {expected_value}")
    
    elif event_type == "encoder_preset_set":
        expected_value = _CONFIG["task_parameters"]["encoder_preset"]
        if message.get("payload", {}).get("value") == expected_value:
            _TASK_STATUS["encoder_preset_set"] = True
            _EVALUATOR.logger.info(f"编码预设已正确设置为 {expected_value}")
    
    elif event_type == "replay_buffer_enabled":
        if message.get("payload", {}).get("value") == 1:
            _TASK_STATUS["replay_buffer_enabled"] = True
            _EVALUATOR.logger.info("回放缓冲区已成功启用")
    
    elif event_type == "replay_time_set":
        expected_value = int(_CONFIG["task_parameters"]["replay_buffer_time"])
        if message.get("payload", {}).get("value") == expected_value:
            _TASK_STATUS["replay_time_set"] = True
            _EVALUATOR.logger.info(f"回放时间已正确设置为 {expected_value}秒")
    
    elif event_type == "evaluate_finished":
        _EVALUATOR.logger.info("评估完成")
    
    # 检查任务是否已全部完成
    return check_task_completion()

def register_handlers(evaluator):
    """
    注册所有事件处理函数到评估器
    
    Args:
        evaluator: 评估器实例
        
    Returns:
        message_handler: 处理函数
    """
    # 设置全局评估器，用于message_handler
    set_evaluator(evaluator)
    return message_handler