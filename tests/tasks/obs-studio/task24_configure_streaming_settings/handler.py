#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List
import configparser
import os

# Task completion status tracking
_TASK_STATUS = {
    "video_bitrate_set": False,
    "audio_bitrate_set": False,
    "encoder_preset_set": False,
    "replay_buffer_enabled": False,
    "replay_time_set": False
}

key_steps = []

def check_task_completion() -> Optional[List[Dict[str, Any]]]:
    """Check if all tasks have been completed"""
    global key_steps
    all_completed = all(_TASK_STATUS.values())
    
    if all_completed:
        key_steps.append({"status": "success", "reason": "All settings have been successfully completed"})
        return key_steps
    return None

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global key_steps
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"Received event: {event_type}")
    
    # Handle various event types
    if event_type == "video_bitrate_set":
        expected_value = int(task_parameter["video_bitrate"])
        if payload.get("value") == expected_value:
            _TASK_STATUS["video_bitrate_set"] = True
            key_steps.append({"status": "key_step", "index": 1})
            logger.info(f"Video bitrate has been correctly set to {expected_value}Kbps")
    
    elif event_type == "audio_bitrate_set":
        expected_value = int(task_parameter["audio_bitrate"])
        if int(payload.get("value")) == expected_value:
            _TASK_STATUS["audio_bitrate_set"] = True
            key_steps.append({"status": "key_step", "index": 2})
            logger.info(f"Audio bitrate has been correctly set to {expected_value}")
    
    elif event_type == "encoder_preset_set":
        expected_value = task_parameter["encoder_preset"]
        if payload.get("value") == expected_value:
            _TASK_STATUS["encoder_preset_set"] = True
            key_steps.append({"status": "key_step", "index": 3})
            logger.info(f"Encoder preset has been correctly set to {expected_value}")
    
    elif event_type == "replay_buffer_enabled":
        if payload.get("value") == 1:
            _TASK_STATUS["replay_buffer_enabled"] = True
            key_steps.append({"status": "key_step", "index": 4})
            logger.info("Replay buffer has been successfully enabled")
    
    elif event_type == "replay_time_set":
        expected_value = int(task_parameter["replay_buffer_time"])
        if payload.get("value") == expected_value:
            _TASK_STATUS["replay_time_set"] = True
            key_steps.append({"status": "key_step", "index": 5})
            logger.info(f"Replay time has been correctly set to {expected_value} seconds")
        
    elif event_type == "config_saved":
        config_file = payload.get("configFile")

        # Check if the ini file exists
        if os.path.exists(config_file):
            config = configparser.ConfigParser()
            config.read(config_file)
            # Check if the SimpleOutput section exists
            if config.has_section('SimpleOutput'):
                # Use configparser's interface to check the SimpleOutput section's configuration
                section = 'SimpleOutput'
                
                # Check video bitrate setting
                if config.has_option(section, 'VBitrate'):
                    expected_video_bitrate = int(task_parameter["video_bitrate"])
                    actual_video_bitrate = config.getint(section, 'VBitrate')
                    if actual_video_bitrate == expected_video_bitrate:
                        logger.info(f"Video bitrate in the configuration file has been correctly set to {expected_video_bitrate}Kbps")
                        _TASK_STATUS["video_bitrate_set"] = True
                        if not dict_have_index(key_steps, 1):
                            key_steps.append({"status": "key_step", "index": 1})
                    else:
                        logger.warning(f"Video bitrate setting in the configuration file is incorrect: {actual_video_bitrate}")
                        
                # Check audio bitrate setting
                if config.has_option(section, 'ABitrate'):
                    expected_audio_bitrate = int(task_parameter["audio_bitrate"])
                    actual_audio_bitrate = config.getint(section, 'ABitrate')
                    if actual_audio_bitrate == expected_audio_bitrate:
                        logger.info(f"Audio bitrate in the configuration file has been correctly set to {expected_audio_bitrate}")
                        _TASK_STATUS["audio_bitrate_set"] = True
                        if not dict_have_index(key_steps, 2):
                            key_steps.append({"status": "key_step", "index": 2})
                    else:
                        logger.warning(f"Audio bitrate setting in the configuration file is incorrect: {actual_audio_bitrate}")
                        
                # Check encoder preset
                if config.has_option(section, 'Preset'):
                    expected_preset = task_parameter["encoder_preset"]
                    actual_preset = config.get(section, 'Preset')
                    if actual_preset == expected_preset:
                        logger.info(f"Encoder preset in the configuration file has been correctly set to {expected_preset}")
                        _TASK_STATUS["encoder_preset_set"] = True
                        if not dict_have_index(key_steps, 3):
                            key_steps.append({"status": "key_step", "index": 3})
                    else:
                        logger.warning(f"Encoder preset setting in the configuration file is incorrect: {actual_preset}")
                        
                # Check replay buffer enabled status
                if config.has_option(section, 'RecRB'):
                    is_enabled = config.getboolean(section, 'RecRB')
                    if is_enabled:
                        logger.info("Replay buffer has been successfully enabled in the configuration file")
                        _TASK_STATUS["replay_buffer_enabled"] = True
                        if not dict_have_index(key_steps, 4):
                            key_steps.append({"status": "key_step", "index": 4})
                    else:
                        logger.warning("Replay buffer is not enabled in the configuration file")
                        
                # Check replay time setting
                if config.has_option(section, 'RecRBTime'):
                    expected_replay_time = int(task_parameter["replay_buffer_time"])
                    actual_replay_time = config.getint(section, 'RecRBTime')
                    if actual_replay_time == expected_replay_time:
                        logger.info(f"Replay time in the configuration file has been correctly set to {expected_replay_time} seconds")
                        _TASK_STATUS["replay_time_set"] = True
                        if not dict_have_index(key_steps, 5):
                            key_steps.append({"status": "key_step", "index": 5})
                    else:
                        logger.warning(f"Replay time setting in the configuration file is incorrect: {actual_replay_time}")

    # Check if all tasks have been completed
    return check_task_completion()

def dict_have_index(key_steps: List[Dict[str, Any]], index: int) -> bool:
    for key_step in key_steps:
        if "index" in key_step and key_step["index"] == index:
            return True
    
    return False