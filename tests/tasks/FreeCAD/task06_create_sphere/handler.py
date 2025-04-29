#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FreeCAD Sphere Creation Task Event Handler
Responsible for processing events from the hook script and returning status updates
"""
from typing import Dict, Any, Optional, List

# Event type constants
SCRIPT_INITIALIZED = "script_initialized"
FUNCTION_NOT_FOUND = "function_not_found"
FUNCTION_FOUND = "function_found"
FUNCTION_CALLED = "function_called"
FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected"
ERROR = "error"
HOOK_INSTALLED = "hook_installed"

# Keyword related constants
RADIUS = "radius"

def execute_python_code(code: str, logger: Any) -> Dict[str, Any]:
    """
    Execute Python code and return the results
    """
    try:
        namespace = {}
        exec(code, namespace)
        result = namespace.get('result', None)
        if result is None:
            logger.warning("Sphere object not found")
            return None
        if RADIUS not in result:
            logger.error(f"Result missing required key: {RADIUS}")
            return None
        return result
    except Exception as e:
        logger.error(f"Error executing Python code: {str(e)}")
        return None

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Process messages received from the hook script
    
    Args:
        message: Frida message object
        logger: Logger
        task_parameter: Task parameters
        
    Returns:
        Optional[List[Dict[str, Any]]]: List of status updates, or None if no updates
    """
    updates = []
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        if 'event' in payload:
            event_type = payload['event']
            logger.debug(f"Received event: {event_type}")
            if event_type == SCRIPT_INITIALIZED:
                logger.info(f"Hook script initialized: {payload.get('message', '')}")
            elif event_type == FUNCTION_FOUND:
                logger.info(f"Function found: {payload.get('address', '')}")
            elif event_type == FUNCTION_CALLED:
                logger.info(f"Function called: {payload.get('message', '')}")
                updates.append({
                    'status': 'key_step',
                    'index': 1,
                    'name': 'Save document'
                })
            elif event_type == FUNCTION_KEY_WORD_DETECTED:
                code = payload.get('code', '')
                filename = payload.get('filename', '')
                expected_path = task_parameter.get("source_path", "") + task_parameter.get("filename", "")
                logger.info(f"Keyword detected, document path: {filename}, expected path: {expected_path}")
                if filename == expected_path:
                    result = execute_python_code(code, logger)
                    if result:
                        expected_radius = task_parameter.get(RADIUS, 8)
                        actual_radius = result[RADIUS]
                        logger.debug(f"Expected radius: {expected_radius}, Actual radius: {actual_radius}")
                        if actual_radius == expected_radius:
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': 'Successfully created sphere and saved'
                            })
                            updates.append({
                                'status': 'success',
                                'reason': f'Successfully created a sphere with radius {actual_radius} and saved it'
                            })
            elif event_type == ERROR:
                error_type = payload.get("error_type", "unknown")
                error_message = payload.get("message", "Unknown error")
                logger.error(f"Hook script error ({error_type}): {error_message}")
                updates.append({
                    'status': 'error',
                    'type': error_type,
                    'message': error_message
                })
    elif message.get('type') == 'error':
        logger.error(f"Hook script error: {message.get('stack', '')}")
        updates.append({
            'status': 'error',
            'type': 'script_error',
            'message': message.get('stack', 'Unknown error')
        })
    return updates if updates else None
