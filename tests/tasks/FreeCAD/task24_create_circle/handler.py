#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD Circle Event Handler
Responsible for processing events from hook script and updating evaluation metrics
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
CENTER_X = "center_x"
CENTER_Y = "center_y"
HAS_CIRCLE = "has_circle"

def execute_python_code(code: str, logger: Any) -> Dict[str, Any]:
    """
    Execute Python code and return the result
    
    Args:
        code: Python code to execute
        logger: Logger
        
    Returns:
        Dict[str, Any]: Execution result
    """
    try:
        # Create a new namespace to execute the code
        namespace = {}
        exec(code, namespace)
        result = namespace.get('result', None)
        
        if result is None:
            logger.warning("Circle object not found")
            return None
            
        # Verify result format
        required_keys = [RADIUS, CENTER_X, CENTER_Y, HAS_CIRCLE]
        if not all(key in result for key in required_keys):
            logger.error(f"Result missing required keys: {required_keys}")
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
            logger.debug(f"Event received: {event_type}")
            
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
                # Execute Python code and get results
                code = payload.get('code', '')
                filename = payload.get('filename', '')
                expected_path = task_parameter.get("source_path", "") + task_parameter.get("filename", "")
                logger.info(f"Detected keywords, document path: {filename}, expected document path: {expected_path}")
                
                if filename == expected_path:
                    result = execute_python_code(code, logger)
                    if result:
                        # Check if circle parameters meet expectations
                        expected_radius = task_parameter.get(RADIUS, 10)
                        
                        actual_radius = result[RADIUS]
                        actual_center_x = result[CENTER_X]
                        actual_center_y = result[CENTER_Y]
                        has_circle = result[HAS_CIRCLE]

                        # Log key parameters
                        logger.info(f"Task parameter check: Expected radius {expected_radius}, center should be origin (0,0)")
                        logger.info(f"Actual parameter check: Actual radius {actual_radius}, actual center ({actual_center_x}, {actual_center_y}), circle exists: {has_circle}")

                        # Convert values that might have units to float
                        try:
                            # Try to get the numeric part (handling possible units)
                            actual_radius_value = float(str(actual_radius).split()[0]) if isinstance(actual_radius, str) else float(actual_radius)
                            actual_center_x_value = float(str(actual_center_x).split()[0]) if isinstance(actual_center_x, str) else float(actual_center_x)
                            actual_center_y_value = float(str(actual_center_y).split()[0]) if isinstance(actual_center_y, str) else float(actual_center_y)
                            
                            # Allow a small error range (0.01)
                            radius_error = abs(actual_radius_value - expected_radius) <= 0.01
                            center_x_error = abs(actual_center_x_value) <= 0.01  # Origin x-coordinate is 0
                            center_y_error = abs(actual_center_y_value) <= 0.01  # Origin y-coordinate is 0
                        except Exception as e:
                            logger.error(f"Parameter comparison error: {str(e)}")
                            radius_error = False
                            center_x_error = False
                            center_y_error = False
                        
                        if has_circle and radius_error and center_x_error and center_y_error:
                            # Update second key step status
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': 'Successfully created circle and saved'
                            })
                            
                            # Task completed successfully
                            updates.append({
                                'status': 'success',
                                'reason': 'Successfully created circle with required parameters and saved'
                            })
                        else:
                            logger.warning(f"Parameter validation failed: Expected radius {expected_radius}, center should be origin (0,0)")
                
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
