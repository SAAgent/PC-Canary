#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from typing import Dict, Any, Optional, List

key_steps = []

start_recording = False

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global key_steps, start_recording
    payload = message['payload']
    print(payload)
    event_type = payload['event']
    logger.debug(f"Received event: {event_type}")
    if event_type == "config_file_found":
        config_file_path = payload.get("path", "")
        logger.info(f"Found configuration file path: {config_file_path}")
        
        # Wait for a while to ensure the file has been written
        time.sleep(1)
        
        # Read the configuration file content
        try:
            with open(config_file_path, "r") as f:
                config_content = f.read()
            
            # Parse the configuration file content to find the value of RecFormat2 in the [SimpleOutput] section
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
                    # Already left the [SimpleOutput] section
                    break
                
                if in_simple_output_section and trimmed_line.startswith('RecFormat2='):
                    rec_format2_value = trimmed_line[len('RecFormat2='):]
                
                if in_simple_output_section and trimmed_line.startswith('FilePath='):
                    file_path_value = trimmed_line[len('FilePath='):]
            
            # Check the FilePath value
            if file_path_value is not None:
                logger.info(f"Found FilePath value in the configuration file: {file_path_value}")
                expected_path = task_parameter.get("output_path", "")
                
                if expected_path in file_path_value:
                    key_steps.append({"status":"key_step","index":1})
                    logger.info(f"Recording output path has been correctly configured as: {file_path_value}")
                else:
                    logger.warning(f"Recording output path configuration does not match, expected: {expected_path}, actual: {file_path_value}")
            else:
                logger.warning("FilePath setting not found in the configuration file")
            
            # Check the RecFormat2 value
            if rec_format2_value is not None:
                logger.info(f"Found RecFormat2 value in the configuration file: {rec_format2_value}")
                expected_format = task_parameter.get("output_format", "")
                
                if rec_format2_value == expected_format:
                    key_steps.append({"status":"key_step","index":2})
                    logger.info(f"Recording output format has been correctly configured as: {rec_format2_value}")
                else:
                    logger.warning(f"Recording output format configuration does not match, expected: {expected_format}, actual: {rec_format2_value}")
            else:
                logger.warning("RecFormat2 setting not found in the configuration file")
            
        except Exception as e:
            logger.error(f"Failed to read or parse the configuration file: {str(e)}")

        return key_steps
        
    elif event_type == "output_path_configured":
        # Retain this event handler in case the path is obtained directly from the API
        logger.info("Recording output path obtained through API")
        configured_path = payload.get("path", "")
        expected_path = task_parameter.get("output_path", "")
        
        if expected_path in configured_path:
            logger.info(f"Recording output path has been correctly configured as: {configured_path}")
            if not dict_have_index(key_steps, 1):
                key_steps.append({"status":"key_step","index":1})
        else:
            logger.warning(f"Recording output path configuration does not match, expected: {expected_path}, actual: {configured_path}")
        
        return key_steps
        
    elif event_type == "output_format_configured":
        # Retain this event handler in case the format is obtained directly from the API
        logger.info("Recording output format obtained through API")
        configured_format = payload.get("format", "")
        expected_format = task_parameter.get("output_format", "")
        
        if configured_format == expected_format:
            if not dict_have_index(key_steps, 2):
                key_steps.append({"status":"key_step","index":2})
            logger.info(f"Recording output format has been correctly configured as: {configured_format}")
        else:
            logger.warning(f"Recording output format configuration does not match, expected: {expected_format}, actual: {configured_format}")
        
        return key_steps

    elif event_type == "start_recording_called":
        start_recording = True
        logger.info("Recording started")

    elif event_type == "stop_recording_called":
        # If both start and stop recording are called, consider the recording functionality tested
        if start_recording:
            if not dict_have_index(key_steps, 3):
                key_steps.append({"status":"key_step","index":3})
            logger.info("Recording functionality successfully tested")
            print(key_steps)
            # Check if all success conditions are met
            if len(key_steps) == 3:
                key_steps.append({"status":"success", "reason": "Output path and format both match, and recording test completed"})
                return key_steps
    
    return None

def dict_have_index(key_steps: List[Dict[str, Any]], index: int) -> bool:
    # Check if the key step with the given index exists in the list
    for key_step in key_steps:
        if "index" in key_step and key_step["index"] == index:
            return True
    
    return False
