#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    info = message.get('hasErrors', {})
    fileName = info.get('fileName', None)
    hasErrors = info.get('hasErrors', None)
    content = info.get('content', None)
    expected_file_content = task_parameter.get("expected_file_content", "#include<iostream>#include<vector>voidInsertionSort(std::vector<int>&Array){intArraySize=Array.size();for(intI=1;I<ArraySize;I++){intKey=Array[I];intJ=I-1;while(J>=0&&Array[J]>Key){Array[J+1]=Array[J];J--;}Array[J+1]=Key;}}intmain(){std::vector<int>InputArray={64,34,25,12,22,11,90};InsertionSort(InputArray);for(intNum:InputArray){std::cout<<Num<<\"\";}std::cout<<std::endl;return0;}")
    expected_file_path = task_parameter.get("expected_file_path", "/root/C-Plus-Plus/agent_test/change_name.cpp")
    logger.info(message.get('message'))
    if event_type == 'evaluate_on_completion' and fileName == expected_file_path and hasErrors == False:
        if ''.join(content.split()) == expected_file_content:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None
