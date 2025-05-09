#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, Callable, List
import configparser
import os

# 任务完成状态跟踪
_TASK_STATUS = {
    "video_bitrate_set": False,
    "audio_bitrate_set": False,
    "encoder_preset_set": False,
    "replay_buffer_enabled": False,
    "replay_time_set": False
}

key_steps = []

def check_task_completion() -> Optional[List[Dict[str, Any]]]:
    """检查任务是否已全部完成"""
    global key_steps
    all_completed = all(_TASK_STATUS.values())
    
    if all_completed:
        key_steps.append({"status": "success", "reason": "所有设置已成功完成"})
        return key_steps
    return None

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global key_steps
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"接收到事件: {event_type}")
    
    # 处理各种事件类型
    if event_type == "video_bitrate_set":
        expected_value = int(task_parameter["video_bitrate"])
        if payload.get("value") == expected_value:
            _TASK_STATUS["video_bitrate_set"] = True
            key_steps.append({"status": "key_step", "index": 1})
            logger.info(f"视频比特率已正确设置为 {expected_value}Kbps")
    
    elif event_type == "audio_bitrate_set":
        expected_value = int(task_parameter["audio_bitrate"])
        if int(payload.get("value")) == expected_value:
            _TASK_STATUS["audio_bitrate_set"] = True
            key_steps.append({"status": "key_step", "index": 2})
            logger.info(f"音频比特率已正确设置为 {expected_value}")
    
    elif event_type == "encoder_preset_set":
        expected_value = task_parameter["encoder_preset"]
        if payload.get("value") == expected_value:
            _TASK_STATUS["encoder_preset_set"] = True
            key_steps.append({"status": "key_step", "index": 3})
            logger.info(f"编码预设已正确设置为 {expected_value}")
    
    elif event_type == "replay_buffer_enabled":
        if payload.get("value") == 1:
            _TASK_STATUS["replay_buffer_enabled"] = True
            key_steps.append({"status": "key_step", "index": 4})
            logger.info("回放缓冲区已成功启用")
    
    elif event_type == "replay_time_set":
        expected_value = int(task_parameter["replay_buffer_time"])
        if payload.get("value") == expected_value:
            _TASK_STATUS["replay_time_set"] = True
            key_steps.append({"status": "key_step", "index": 5})
            logger.info(f"回放时间已正确设置为 {expected_value}秒")
        
    elif event_type == "config_saved":
        config_file = payload.get("configFile")

        # 检查ini文件是否存在
        if os.path.exists(config_file):
            config = configparser.ConfigParser()
            config.read(config_file)
            # 检查SimpleOutput节是否存在
            if config.has_section('SimpleOutput'):
                # 使用configparser的接口检查SimpleOutput节的配置
                section = 'SimpleOutput'
                
                # 检查视频比特率设置
                if config.has_option(section, 'VBitrate'):
                    expected_video_bitrate = int(task_parameter["video_bitrate"])
                    actual_video_bitrate = config.getint(section, 'VBitrate')
                    if actual_video_bitrate == expected_video_bitrate:
                        logger.info(f"配置文件中视频比特率已正确设置为 {expected_video_bitrate}Kbps")
                        _TASK_STATUS["video_bitrate_set"] = True
                        if not dict_have_index(key_steps, 1):
                            key_steps.append({"status": "key_step", "index": 1})
                    else:
                        logger.warning(f"配置文件中视频比特率设置不正确: {actual_video_bitrate}")
                        
                # 检查音频比特率设置
                if config.has_option(section, 'ABitrate'):
                    expected_audio_bitrate = int(task_parameter["audio_bitrate"])
                    actual_audio_bitrate = config.getint(section, 'ABitrate')
                    if actual_audio_bitrate == expected_audio_bitrate:
                        logger.info(f"配置文件中音频比特率已正确设置为 {expected_audio_bitrate}")
                        _TASK_STATUS["audio_bitrate_set"] = True
                        if not dict_have_index(key_steps, 2):
                            key_steps.append({"status": "key_step", "index": 2})
                    else:
                        logger.warning(f"配置文件中音频比特率设置不正确: {actual_audio_bitrate}")
                        
                # 检查编码器预设
                if config.has_option(section, 'Preset'):
                    expected_preset = task_parameter["encoder_preset"]
                    actual_preset = config.get(section, 'Preset')
                    if actual_preset == expected_preset:
                        logger.info(f"配置文件中编码预设已正确设置为 {expected_preset}")
                        _TASK_STATUS["encoder_preset_set"] = True
                        if not dict_have_index(key_steps, 3):
                            key_steps.append({"status": "key_step", "index": 3})
                    else:
                        logger.warning(f"配置文件中编码预设设置不正确: {actual_preset}")
                        
                # 检查回放缓冲区启用状态
                if config.has_option(section, 'RecRB'):
                    is_enabled = config.getboolean(section, 'RecRB')
                    if is_enabled:
                        logger.info("配置文件中回放缓冲区已成功启用")
                        _TASK_STATUS["replay_buffer_enabled"] = True
                        if not dict_have_index(key_steps, 4):
                            key_steps.append({"status": "key_step", "index": 4})
                    else:
                        logger.warning("配置文件中回放缓冲区未启用")
                        
                # 检查回放时间设置
                if config.has_option(section, 'RecRBTime'):
                    expected_replay_time = int(task_parameter["replay_buffer_time"])
                    actual_replay_time = config.getint(section, 'RecRBTime')
                    if actual_replay_time == expected_replay_time:
                        logger.info(f"配置文件中回放时间已正确设置为 {expected_replay_time}秒")
                        _TASK_STATUS["replay_time_set"] = True
                        if not dict_have_index(key_steps, 5):
                            key_steps.append({"status": "key_step", "index": 5})
                    else:
                        logger.warning(f"配置文件中回放时间设置不正确: {actual_replay_time}")

    
    # 检查任务是否已全部完成
    return check_task_completion()

def dict_have_index(key_steps: List[Dict[str, Any]], index: int) -> bool:
    for key_step in key_steps:
        if "index" in key_step and key_step["index"] == index:
            return True
    
    return False