import os
import json
import time
from typing import Dict, Any, Optional, Callable

# 全局评估器实例，由message_handler使用
_EVALUATOR = None
_CONFIG = None
_START_TIME = None

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator
    
    # 使用评估器的已更新配置，而不是重新读取文件
    if hasattr(evaluator, 'config') and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("使用评估器中的更新配置")
    else:
        # 作为备份，如果评估器中没有配置，才从文件读取
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "config.json")
            
            with open(config_file, 'r') as f:
                _CONFIG = json.load(f)
                _EVALUATOR.logger.info("从文件加载配置")
        except Exception as e:
            if _EVALUATOR:
                _EVALUATOR.logger.error(f"加载配置文件失败: {str(e)}")

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: injector消息对象
        data: 附加数据
        
    Returns:
        str: 如果任务成功完成返回"success"，否则返回None
    """
    global _EVALUATOR, _CONFIG, _START_TIME
    
    # 初始化开始时间
    if _START_TIME is None:
        _START_TIME = time.time()
    
    # 检查评估器是否已设置
    if _EVALUATOR is None:
        print("警告: 评估器未设置，无法处理消息")
        return None
    # TODO:
    event_type = message.get('event_type')
    if event_type == 'pdf_reader_changed':
        # 检查 PDF 阅读器是否已更改
        if check_pdf_file_handler_setting(message):
            _EVALUATOR.update_metric("success", True)
            return "success"
    else:
        _EVALUATOR.update_metric("error", {"type": "unknown", "message": "未知错误"})
        return "error"

def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler


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
