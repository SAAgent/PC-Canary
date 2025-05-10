import os
import json
import time
from typing import Dict, Any, Optional, Set, Dict, Union, Tuple
import enum


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
    if event_type == 'reference_exported':
        status = check_files_existence()
        if status == FileCheckStatus.ALL_EXIST:
            _EVALUATOR.update_metric("success", True)
            return "success"
        #TODO: 这里的update_metric方法需要根据实际情况进行调整
        elif status == FileCheckStatus.NOT_ALL_EXIST:
            _EVALUATOR.update_metric("error", {"type": "file_not_found", "message": "文件不存在"})
            return "error"
        elif status == FileCheckStatus.INCREASING:
            _EVALUATOR.update_metric("error", {"type": "file_increasing", "message": "文件数量增加"})
            return "error"
    else:
        _EVALUATOR.update_metric("error", {"type": "unknown", "message": "未知错误"})
        return "error"

def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler

# 定义状态枚举
class FileCheckStatus(enum.Enum):
    NOT_ALL_EXIST = 0      # 不是所有文件都存在
    INCREASING = 1         # 比上次多了文件
    ALL_EXIST = 2          # 所有文件都存在

# 假设这是全局的文件路径集合
global_file_paths: Set[str] = set(
    ['/home/agent/test.rtf']
)

# 保存状态的字典
_state = {
    'last_existing_files': set(),  # 上次检查时存在的文件
    'last_check_count': 0,         # 上次检查时存在的文件数量
}

def check_files_existence() -> FileCheckStatus:
    """
    检查全局集合中的文件路径是否都存在
    
    返回:
        FileCheckStatus.NOT_ALL_EXIST: 不是所有文件都存在
        FileCheckStatus.INCREASING: 比上次检查多了文件，但还不是全部
        FileCheckStatus.ALL_EXIST: 所有文件都存在
    """
    # 检查哪些文件路径实际存在
    existing_files = {path for path in global_file_paths if os.path.exists(path)}
    existing_count = len(existing_files)
    total_count = len(global_file_paths)
    
    # 检查是否有新文件出现
    new_files = existing_files - _state['last_existing_files']
    
    # 如果有正好一个新文件，记录它的路径
    if len(new_files) == 1:
        new_file_path = next(iter(new_files))
        print(f"检测到新文件: {new_file_path}")
    elif len(new_files) > 1:
        print(f"检测到多个新文件: {new_files}")
    
    # 更新状态
    _state['last_existing_files'] = existing_files.copy()
    
    # 确定返回状态
    if existing_count == total_count:
        # 所有文件都存在
        status = FileCheckStatus.ALL_EXIST
    elif existing_count > _state['last_check_count']:
        # 比上次多了文件，但还不是全部
        status = FileCheckStatus.INCREASING
    else:
        # 没有新增文件，且不是所有文件都存在
        status = FileCheckStatus.NOT_ALL_EXIST
    
    # 更新上次检查的计数
    _state['last_check_count'] = existing_count
    
    return status