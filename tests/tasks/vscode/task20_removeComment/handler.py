#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
vscode修改主题颜色的事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os, re
import json
import time
from typing import Dict, Any, Optional, List

_EXPECTED_FILE = None
LOGGER = None

def find_cpp_file(directory, target_file):
    """
    Recursively search for a file named 'target_file' in the specified directory.
    Returns the absolute path of the first matching file, or None if not found.
    
    Args:
        directory (str): The root directory to start the search.
    
    Returns:
        str or None: Absolute path of the first 'target_file' file found, or None if not found.
    """
    try:
        # Ensure directory is absolute
        directory = os.path.abspath(directory)
        
        # Check if directory exists
        if not os.path.isdir(directory):
            raise ValueError(f"Directory '{directory}' does not exist.")
        
        # Recursive helper function
        def search_recursive(current_dir):
            try:
                # List all entries in the current directory
                for entry in os.listdir(current_dir):
                    entry_path = os.path.join(current_dir, entry)
                    
                    # If it's a file and matches target_file, return its path
                    if os.path.isfile(entry_path) and entry == target_file:
                        return entry_path
                    
                    # If it's a directory, recurse into it
                    if os.path.isdir(entry_path):
                        result = search_recursive(entry_path)
                        if result:
                            return result
                return None
            except PermissionError:
                # Skip directories with permission issues
                return None
            except Exception as e:
                raise RuntimeError(f"Error searching in {current_dir}: {str(e)}")
        
        return search_recursive(directory)
    
    except Exception as e:
        raise RuntimeError(f"Error searching for xxx.cpp: {str(e)}")

def remove_comments(content):
    """
    Removes C++ comments (single-line and multi-line) from the given content.
    Preserves string literals and returns non-comment content.
    
    Args:
        content (str): The C++ file content.
    
    Returns:
        str: The content with comments removed.
    """
    try:
        # Regex to match string literals (double and single quotes) and comments
        # - Group 1: String literals ("..." or '...')
        # - Non-capturing groups for comments: //... and /*...*/
        pattern = r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')|//.*?$|/\*[\s\S]*?\*/'
        
        # Replace comments with empty string, keep string literals
        result = re.sub(pattern, lambda m: m.group(1) if m.group(1) else '', content, flags=re.MULTILINE)
        
        # Optionally remove empty lines and trim
        result = '\n'.join(line for line in result.split('\n') if line.strip())
        LOGGER.info(result)
        return result.split()
    except Exception as e:
        raise RuntimeError(f"Error removing comments: {str(e)}")


def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    global _EXPECTED_FILE, LOGGER

    event_type = message.get('event_type')
    LOGGER = logger
    # _EVALUATOR.logger.info(message)
    logger.info(message)
    expected_file_path = task_parameter.get("expected_file_path")
    if event_type == 'get_origin_file':
        root = message.get('root', None)
        if root == None:
            return None
        expected_file = task_parameter.get("file", "get_size_of_linked_list.cpp")
        file_path = find_cpp_file(root, expected_file)
        with open(file_path, "r", encoding="UTF8") as f:
            content = f.read()
        _EXPECTED_FILE = ''.join(remove_comments(content))
    elif event_type == "evaluate_on_completion":
        root = message.get('root', None)
        if root == None:
            return None
        expected_file = task_parameter.get("file", "get_size_of_linked_list.cpp")
        file_path = find_cpp_file(root, expected_file)
        with open(file_path, "r", encoding="UTF8") as f:
            content = f.read()
        file_content = ''.join(content.split())
        if file_content == _EXPECTED_FILE and message.get('filename', None) == file_path:
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    elif event_type == "open_file":
        file_path = message.get("path")
        if message.get("scheme") == "git":
            file_path = file_path[:-4]
        if file_path == expected_file_path:
            return [{"status": "key_step", "index": 1}]
    return None
