import os
import json
import time
from typing import Dict, Any, Optional, Set, Dict, List
import enum


def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    if event_type == 'reference_exported':
        status = check_files_existence()
        if status == FileCheckStatus.ALL_EXIST:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "所有文件都存在"}
            ]
        #TODO: 这里的update_metric方法需要根据实际情况进行调整
        elif status == FileCheckStatus.NOT_ALL_EXIST:
            return None
        elif status == FileCheckStatus.INCREASING:
            return None
    else:
        return [
            {"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}
        ]

# 定义状态枚举
class FileCheckStatus(enum.Enum):
    NOT_ALL_EXIST = 0      # 不是所有文件都存在
    INCREASING = 1         # 比上次多了文件
    ALL_EXIST = 2          # 所有文件都存在

# 假设这是全局的文件路径集合
# TODO: 可能需要修改为实际的文件路径
global_file_paths: Set[str] = set(
    ['/home/agent/export-reference/Multi-Grained.rtf']
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