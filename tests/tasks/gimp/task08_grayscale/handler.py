#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GIMP转换为灰度模式任务事件处理器
负责处理钩子脚本产生的事件并更新评估指标
"""

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    # 处理包装的事件数据结构
    if message.get('type') == 'send':
        message = message.get('payload', {})
    
    event_type = message.get('event_type')
    logger.info(f"收到事件: {event_type}, 消息内容: {message}")
    
    if event_type == "image_converted":
        # 检查是否转换为灰度模式
        if message.get('new_type') == 1:  # GIMP_GRAY = 1
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "成功将图像转换为灰度模式"}
            ]
    
    return None 