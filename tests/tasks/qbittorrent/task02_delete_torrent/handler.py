#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
QBittorrent添加种子文件任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional

# 全局评估器实例
_EVALUATOR = None 
_CONFIG = None
_START_TIME = None

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator
    
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(current_dir, "config.json")
        
        with open(config_file, 'r') as f:
            _CONFIG = json.load(f)
            print(f"加载配置文件: {config_file}")
    except Exception as e:
        if _EVALUATOR:
            _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: Frida消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _EVALUATOR, _CONFIG, _START_TIME
    
    if _START_TIME is None:
        _START_TIME = time.time()
    
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None

    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        if 'event' in payload:
            event_type = payload['event']
            _EVALUATOR.logger.debug(f"接收到事件: {event_type}")
            
            _EVALUATOR.record_event(event_type, payload)
            
            if event_type == "script_initialized":
                _EVALUATOR.logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == "function_found":
                _EVALUATOR.logger.info(f"找到了目标函数 :{payload.get('address', '')}")
                _EVALUATOR.update_metric("found_group", True)
                
            elif event_type == "add_torrent_called":
                result = payload.get("torrent_data", "")
                _EVALUATOR.logger.info(f"拦截到删除会话框种子函数调用: {result}")
                

            elif event_type == "remove_torrent_result":
                result = payload.get("result","")
                if result:
                    _EVALUATOR.update_metric("correct_file", True)
                    _EVALUATOR.logger.info("添加的是目标文件!")
                
            elif event_type == "error":
                error_type = payload.get("error_type", "unknown")
                message = payload.get("message", "未知错误")
                
                _EVALUATOR.logger.error(f"钩子脚本错误 ({error_type}): {message}")
                _EVALUATOR.update_metric("error", {"type": error_type, "message": message})
                
    elif message.get('type') == 'error':
        _EVALUATOR.logger.error(f"钩子脚本错误: {message.get('stack', '')}")
    
    return None

def register_handlers(evaluator):
    """注册事件处理器"""
    set_evaluator(evaluator)
    return message_handler