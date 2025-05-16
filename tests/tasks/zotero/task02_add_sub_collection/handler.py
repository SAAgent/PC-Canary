import os
import json
import time
from typing import Dict, Any, Optional, Callable, List
import shutil
import sqlite3
import platform

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    if event_type == 'sub_collection_added':
        if check_libos_in_virtualization():
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "libos 子分类已成功添加"}
            ]
        else:
            return None
    else:
        return [
            {"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}
        ]

# 根据操作系统找到 Zotero 数据库路径
def get_zotero_db_path():
    system = platform.system()
    home = os.path.expanduser("~")
    
    if system == 'Windows':
        return os.path.join(home, 'Zotero', 'zotero.sqlite')
    elif system == 'Darwin':  # macOS
        return os.path.join(home, 'Zotero', 'zotero.sqlite')
    elif system == 'Linux':
        return os.path.join(home, 'Zotero', 'zotero.sqlite')
    else:
        raise Exception("不支持的操作系统")

# 检查 virtualization 分类下是否有 libos 子分类
def check_libos_in_virtualization():
    try:
        # 获取原始数据库路径
        original_db_path = get_zotero_db_path()
        if not os.path.exists(original_db_path):
            print(f"Zotero 数据库文件未找到: {original_db_path}")
            return False
        
        # 创建临时数据库副本
        temp_db_path = original_db_path + ".temp"
        print(f"创建数据库临时副本: {temp_db_path}")
        shutil.copy2(original_db_path, temp_db_path)
        
        try:
            # 连接到临时数据库副本
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # 首先找到 virtualization 分类的 ID
            cursor.execute("""
                SELECT collectionID 
                FROM collections 
                WHERE collectionName LIKE '%virtualization%'
            """)
            
            virtualization_ids = cursor.fetchall()
            
            if not virtualization_ids:
                print("未找到 virtualization 分类")
                return False
            
            # 检查是否有任何 virtualization 分类包含 libos 子分类
            has_libos = False
            
            for virtualization_id in virtualization_ids:
                vid = virtualization_id[0]
                
                # 查找该 virtualization 分类下名为 libos 的子分类
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM collections 
                    WHERE parentCollectionID = ? AND collectionName LIKE '%libos%'
                """, (vid,))
                
                count = cursor.fetchone()[0]
                
                if count > 0:
                    print(f"在 virtualization 分类 (ID: {vid}) 下找到了 libos 子分类")
                    has_libos = True
                    break
            
            conn.close()
            return has_libos
            
        except sqlite3.Error as e:
            print(f"查询数据库时出错: {e}")
            return False
            
        finally:
            # 无论查询是否成功，都删除临时数据库
            if os.path.exists(temp_db_path):
                try:
                    os.remove(temp_db_path)
                    print(f"已删除临时数据库副本")
                except OSError as e:
                    print(f"删除临时数据库时出错: {e}")
    
    except Exception as e:
        print(f"检查 libos 子分类时出错: {e}")
        return False