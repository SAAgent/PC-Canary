#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    logger.info(message)
    expected_hit_file = task_parameter.get("expected_hit_file", '/root/C-Plus-Plus/agent_test/debug_until.cpp')
    expected_hit_line = task_parameter.get("expected_hit_line", 22)
    expected_locals = task_parameter.get("expected_locals", {
        "next": "5",
        "place": "1",
        "i": "5",
        "n": "10",
        "k": "2",
        "seq.[0]": "3",
        "seq.[1]": "2",
    })
    expected_breakpoints = task_parameter.get("breakpoints", {
        "17": "i==3",
        "19": "j==2",
        "22": ""
    })
    expected_program = task_parameter.get("expected_program", "/root/C-Plus-Plus/agent_test/debug_until")
    if event_type == "evaluate_on_completion":
        breakpoints = message.get('breakpoints')
        debuginfo = message.get('debuginfo')
        if not debuginfo or not breakpoints:
            return None
        for bp in breakpoints:
            file = bp.get('file', None)
            line = str(bp.get('line', None))
            condition = bp.get('condition', None)
            if file == expected_hit_file and expected_breakpoints.get(line, None) == condition:
                expected_breakpoints.pop(line)
        if debuginfo.get('file', None) != expected_hit_file or debuginfo.get('line', None) != expected_hit_line:
            return None
        for v in debuginfo.get('locals', []):
            name = v.get('name', None)
            value = v.get('value', None)
            if expected_locals.get(name, None) == value:
                expected_locals.pop(name)
        if len(expected_locals) == 0 and len(expected_breakpoints) == 0:
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
        if file_path == expected_hit_file:
            return [{"status": "key_step", "index": 1}]
    elif event_type == "breakpoint_change":
        bp_file_path = message.get("path")
        bp_file_line = message.get("line")
        bp_condition = message.get("condition")
        bp_enabled = message.get("enabled")
        if bp_file_path != expected_hit_file:
            return None
        if bp_file_line == 17 and bp_enabled and bp_condition == expected_breakpoints.get("17"):
            return [{"status": "key_step", "index": 2}]
        elif bp_file_line == 19 and bp_enabled and bp_condition == expected_breakpoints.get("19"):
            return [{"status": "key_step", "index": 3}]
        elif bp_file_line == 22 and bp_enabled and bp_condition == expected_breakpoints.get("22"):
            return [{"status": "key_step", "index": 4}]
    elif event_type == "debug_session_start":
        program = message.get("program")
        if program == expected_program:
            return [{"status": "key_step", "index": 5}]
    return None
