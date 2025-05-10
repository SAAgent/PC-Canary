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
    if event_type == 'font_size_changed_bigger':
        if check_font_size_increased(message):
            _EVALUATOR.update_metric("success", True)
            return "success"
    else:
        _EVALUATOR.update_metric("error", {"type": "unknown", "message": "未知错误"})
        return "error"


def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler


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