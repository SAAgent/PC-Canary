#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, Callable, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message)
    expected_filename = task_parameter.get("file_name", "/root/C-Plus-Plus/sorting/bubble_sort.cpp")
    expected_breakpoints = task_parameter.get("breakpoints", {
        "78": "i==2",
        "80": "None",
        "98": "None"
    })
    expected_hit_file = task_parameter.get("hit_file", "/root/C-Plus-Plus/sorting/bubble_sort.cpp")
    expected_hit_line = task_parameter.get("hit_line", 98)
    expected_program = task_parameter.get("expected_program", "/root/C-Plus-Plus/sorting/bubble_sort")
    if event_type == "evaluate_on_completion":
        breakpoints_info = message.get('breakpoints')
        current_file = message.get('current_file')
        current_line = message.get('current_line')
        for bp in breakpoints_info:
            file_name = bp['file']
            line = str(bp['line'])
            condition = bp['condition']
            enabled = bp['enabled']
            if file_name == expected_filename and line in expected_breakpoints:
                if enabled and condition == expected_breakpoints[line]:
                    # right settings
                    expected_breakpoints.pop(line)
        if len(expected_breakpoints) == 0 and expected_hit_file == current_file and expected_hit_line == current_line:
            return [
                {"status": "key_step", "index": 6},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    elif event_type == "open_file":
        file_path = message.get("path")
        if message.get("scheme") == "git":
            file_path = file_path[:-4]
        if file_path == expected_filename:
            return [{"status": "key_step", "index": 1}]
    elif event_type == "breakpoint_change":
        bp_file_path = message.get("path")
        bp_file_line = message.get("line")
        bp_condition = message.get("condition")
        bp_enabled = message.get("enabled")
        if bp_file_path != expected_filename:
            return None
        if bp_file_line == 78 and bp_enabled and bp_condition == expected_breakpoints.get("78"):
            return [{"status": "key_step", "index": 2}]
        elif bp_file_line == 80 and bp_enabled and bp_condition == expected_breakpoints.get("80"):
            return [{"status": "key_step", "index": 3}]
        elif bp_file_line == 98 and bp_enabled and bp_condition == expected_breakpoints.get("98"):
            return [{"status": "key_step", "index": 4}]
    elif event_type == "debug_session_start":
        program = message.get("program")
        if program == expected_program:
            return [{"status": "key_step", "index": 5}]
    return None
