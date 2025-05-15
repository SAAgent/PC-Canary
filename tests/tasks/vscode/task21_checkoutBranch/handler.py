#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

LAST_COMMIT = None
HAS_CHANGES = None

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    global HAS_CHANGES, LAST_COMMIT
    event_type = message.get('event_type')
    # _EVALUATOR.logger.info(message)
    logger.info(message)
    expect_branchname = task_parameter.get("branch_name", "gh-pages")
    expect_commitmessage = task_parameter.get("commit_message", "temp commit for checkout")
    expect_origin_branch = task_parameter.get("origin_branch", "master")
    if event_type == 'repo_changed':
        has_changes = message.get('haschanges')
        lastcommit = message.get('lastcommit')
        branchname = message.get('branchname')
        if branchname == expect_origin_branch:
            LAST_COMMIT = lastcommit
            HAS_CHANGES = has_changes
    elif event_type == 'evaluate_on_completion':
        if expect_branchname == message.get('branchname', None) and not HAS_CHANGES and LAST_COMMIT == expect_commitmessage:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None
