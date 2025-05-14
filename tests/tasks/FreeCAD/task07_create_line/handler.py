#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD Event Handler
Responsible for processing events from hook script and determining if the task is complete
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
LENGTH = "length"
FOUND = "found"
HAS_LINE = "has_line"

def execute_python_code(code: str, logger: Any) -> Dict[str, Any]:
    """
    Execute Python code and return results
    
    Args:
        code: Python code to execute
        logger: Logger
        
    Returns:
        Dict[str, Any]: Execution results
    """
    try:
        # Create a new namespace to execute code
        namespace = {}
        exec(code, namespace)
        result = namespace.get('result', None)
        
        if result is None:
            logger.warning("Line object not found")
            return None
            
        return result
    except Exception as e:
        logger.error(f"Error executing Python code: {str(e)}")
        return None

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Process messages received from hook script
    
    Args:
        message: Frida message object
        logger: Logger
        task_parameter: Task parameters
        
    Returns:
        List[Dict[str, Any]]: List of dictionaries containing status updates, or None if there are no updates
    """
    updates = []
    
    # Process message
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        # Check if event type is included
        if 'event' in payload:
            event_type = payload['event']
            logger.debug(f"Received event: {event_type}")
            
            # Handle specific events
            if event_type == SCRIPT_INITIALIZED:
                logger.info(f"Hook script initialized: {payload.get('message', '')}")
                
            elif event_type == FUNCTION_FOUND:
                logger.info(f"Function found: {payload.get('address', '')}")
                
            elif event_type == FUNCTION_CALLED:
                logger.info(f"Function called: {payload.get('message', '')}")
                # Saving document is the first key step
                updates.append({
                    'status': 'key_step',
                    'index': 1,
                    'name': 'Save document'
                })
                
            elif event_type == FUNCTION_KEY_WORD_DETECTED:
                # Execute Python code and get results
                code = payload.get('code', '')
                filename = payload.get('filename', '')
                logger.info(f"Keyword detected, document path: {filename}")
                
                result = execute_python_code(code, logger)
                if result:
                    # Check if sketch was created and has a line
                    if result.get(FOUND, False) and result.get(HAS_LINE, False):
                        # Check if line length matches requirements
                        expected_length = task_parameter.get('line_length', 50.0)
                        actual_length = result.get(LENGTH, 0.0)
                        
                        # Verify length meets requirements
                        if abs(actual_length - expected_length) <= 0.00001:
                            logger.info(f"Line length meets requirements: Expected {expected_length:.2f}, Actual {actual_length:.2f}")
                            
                            # Update second key step status - Line created and saved successfully
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': 'Successfully created line and saved'
                            })
                            
                            # Report task success
                            updates.append({
                                'status': 'success',
                                'reason': f'Successfully created line with length {actual_length:.2f}'
                            })
                            
                            logger.info("Task completed successfully!")
                        else:
                            logger.error(f"Line length does not meet requirements: Expected {expected_length:.2f}, Actual {actual_length:.2f}")
                            
                            updates.append({
                                'status': 'error',
                                'type': 'validation_failed',
                                'message': f'Line length does not meet requirements: Expected {expected_length:.2f}, Actual {actual_length:.2f}'
                            })
                    else:
                        if not result.get(FOUND, False):
                            logger.error("Sketch object not found")
                            updates.append({
                                'status': 'error',
                                'type': 'validation_failed',
                                'message': 'Sketch object not found'
                            })
                        elif not result.get(HAS_LINE, False):
                            logger.error("No line found in sketch")
                            updates.append({
                                'status': 'error',
                                'type': 'validation_failed',
                                'message': 'No line found in sketch'
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