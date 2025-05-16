import os
import json
import time
from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    if event_type == 'pdf_reader_changed':
        # 检查 PDF 阅读器是否已更改
        if check_pdf_file_handler_setting(message):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "PDF 阅读器已成功更改"}
            ]
        else:
            return None
    else:
        return [
            {"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}
        ]


def check_pdf_file_handler_setting(event_data):
    """
    检查事件是否是 Zotero PDF 文件处理器设置的变更
    
    参数:
        event_data (dict): 包含 pref, oldValue, newValue 等字段的事件数据
        
    返回:
        bool: 如果是 PDF 文件处理器设置的变更，则返回 True；否则返回 False
    """
    # 检查参数
    if not isinstance(event_data, dict):
        print("错误: 事件数据不是字典类型")
        return False
        
    pref = event_data.get('pref')
    old_value = event_data.get('oldValue')
    new_value = event_data.get('newValue')
    
    if pref is None:
        print("错误: 事件数据缺少 pref 字段")
        return False
    
    # old_value 和 new_value 可以是 None 或空字符串，表示使用默认处理器
    
    # 检查是否是 PDF 文件处理器设置
    if pref != "extensions.zotero.fileHandler.pdf":
        print(f"首选项 '{pref}' 不是 Zotero PDF 文件处理器设置")
        return False
    
    print(f"检测到 PDF 文件处理器设置变更")
    
    # 处理空值或 None 的情况
    old_value_str = str(old_value) if old_value is not None else "未设置(使用默认处理器)"
    new_value_str = str(new_value) if new_value is not None else "未设置(使用默认处理器)"
    
    print(f"  旧值: {old_value_str}")
    print(f"  新值: {new_value_str}")
    
    # 检查是否切换到默认处理器
    if (new_value is None or new_value == "" or new_value == "null"):
        print("已切换到 Zotero 默认 PDF 处理器")
        return True
    
    # 检查路径是否有效（只在非默认处理器的情况下）
    if not isinstance(new_value, str):
        print("警告: 新的 PDF 处理器路径不是字符串类型")
        # 但我们仍然返回 True，因为这确实是一个处理器变更
        return True
    
    # 检查文件扩展名和路径类型
    if new_value.endswith(".json"):
        print("警告: PDF 处理器路径指向 JSON 文件，这可能不是有效的 PDF 处理器")
    elif new_value.endswith(".pdf"):
        print("警告: PDF 处理器路径指向 PDF 文件，而不是应用程序")
    
    # 检查路径是否变更
    if old_value != new_value:
        if old_value is None or old_value == "" or old_value == "null":
            print(f"PDF 处理器从默认处理器变更为 '{new_value}'")
        else:
            print(f"PDF 处理器路径从 '{old_value}' 变更为 '{new_value}'")
    else:
        print("PDF 处理器路径未变更")
    
    return True
