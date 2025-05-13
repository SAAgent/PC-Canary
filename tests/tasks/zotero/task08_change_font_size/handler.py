import os
import json
import time
from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    if event_type == 'font_size_changed_bigger':
        if check_font_size_increased(message):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "字体大小已成功增加"}
            ]
        else:
            return None
    else:
        return [
            {"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}
        ]


def check_font_size_increased(event_data):
    """
    检查事件是否为 Zotero 字体大小增加的事件
    
    参数:
        event_data (dict): 包含 pref, oldValue, newValue 等字段的事件数据
        
    返回:
        bool: 如果是字体大小增加，则返回 True；否则返回 False
    """
    # 检查参数
    if not isinstance(event_data, dict):
        print("错误: 事件数据不是字典类型")
        return False
        
    pref = event_data.get('pref')
    old_value = event_data.get('oldValue')
    new_value = event_data.get('newValue')
    
    if pref is None or old_value is None or new_value is None:
        print("错误: 事件数据缺少必要字段")
        return False
    
    # 检查是否是 Zotero 字体大小设置
    if pref != "extensions.zotero.fontSize":
        print(f"首选项 '{pref}' 不是 Zotero 字体大小设置")
        return False
    
    # 尝试将值转换为浮点数进行比较
    try:
        # 字体大小通常存储为字符串
        old_size = float(old_value)
        new_size = float(new_value)
        
        if new_size > old_size:
            print(f"Zotero 字体大小增加了: {old_size} -> {new_size}")
            return True
        else:
            print(f"Zotero 字体大小未增加: {old_size} -> {new_size}")
            return False
            
    except (ValueError, TypeError) as e:
        print(f"无法比较字体大小值: {old_value} 和 {new_value}, 错误: {e}")
        return False