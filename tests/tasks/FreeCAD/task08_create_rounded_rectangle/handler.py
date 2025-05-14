#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD rounded rectangle event handler
Handles events sent from the hook script and updates evaluation metrics
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

# Keyword-related constants
LENGTH = "length"
WIDTH = "width"
RADIUS = "radius"

def execute_python_code(code: str, logger: Any) -> Dict[str, Any]:
    """
    Execute Python code and return result
    
    Args:
        code: Python code to execute
        logger: Logger instance
        
    Returns:
        Dict[str, Any]: Execution result
    """
    try:
        # Create a new namespace to execute the code
        namespace = {}
        exec(code, namespace)
        result = namespace.get('result', None)
        
        if result is None:
            logger.warning("Rounded rectangle object not found")
            return None
            
        # Validate result format
        required_keys = [LENGTH, WIDTH, RADIUS]
        if not all(key in result for key in required_keys):
            logger.error(f"Result is missing required keys: {required_keys}")
            return None
            
        return result
    except Exception as e:
        logger.error(f"Error while executing Python code: {str(e)}")
        return None

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Process messages received from the hook script
    
    Args:
        message: Frida message object
        logger: Logger instance
        task_parameter: Task parameters
        
    Returns:
        Optional[List[Dict[str, Any]]]: Status update list, None if no updates
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
                # Update first key step status
                updates.append({
                    'status': 'key_step',
                    'index': 1,
                    'name': 'Save document'
                })
                
            elif event_type == FUNCTION_KEY_WORD_DETECTED:
                # Execute Python code and get result
                code = payload.get('code', '')
                filename = payload.get('filename', '')
                expected_path = task_parameter.get("source_path", "") + task_parameter.get("filename", "")
                logger.info(f"Detected keyword, document path: {filename}, expected document path: {expected_path}")
                
                if filename == expected_path:
                    result = execute_python_code(code, logger)
                    if result:
                        # Check if rounded rectangle dimensions meet expectations
                        expected_length = task_parameter.get(LENGTH, 30)
                        expected_width = task_parameter.get(WIDTH, 20)
                        expected_radius = task_parameter.get(RADIUS, 5)

                        actual_length = result[LENGTH]
                        actual_width = result[WIDTH]
                        actual_radius = result[RADIUS]

                        logger.info(f"Expected dimensions: length={expected_length}, width={expected_width}, corner radius={expected_radius}")
                        logger.info(f"Actual dimensions: length={actual_length}, width={actual_width}, corner radius={actual_radius}")

                        # Allow a certain margin of error (0.01%)
                        length_error = abs((actual_length - expected_length) / expected_length) <= 0.0001
                        width_error = abs((actual_width - expected_width) / expected_width) <= 0.0001
                        radius_error = abs((actual_radius - expected_radius) / expected_radius) <= 0.0001
                        
                        if length_error and width_error and radius_error:
                            # Update second key step status
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': 'Successfully created and saved rounded rectangle'
                            })
                            
                            # Task successfully completed
                            updates.append({
                                'status': 'success',
                                'reason': 'Successfully created a rounded rectangle with required dimensions and saved'
                            })
                        else:
                            logger.warning(f"Rounded rectangle dimensions do not meet requirements: length correct: {length_error}, width correct: {width_error}, corner radius correct: {radius_error}")
                
            elif event_type == ERROR:
                error_type = payload.get("error_type", "unknown")
                error_message = payload.get("message", "Unknown error")
                
                logger.error(f"Hook script error ({error_type}): {error_message}")
                
                # Record error event
                updates.append({
                    'status': 'error',
                    'type': error_type,
                    'message': error_message
                })
                
    elif message.get('type') == 'error':
        logger.error(f"Hook script error: {message.get('stack', '')}")
        
        # Record error event
        updates.append({
            'status': 'error',
            'type': 'script_error',
            'message': message.get('stack', 'Unknown error')
        })
    
    return updates if updates else None