import os
import json
import time
from typing import Dict, Any, Optional, List
import shutil
import sqlite3
import platform

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    if event_type == 'item_restored':
        if check_item_restored_from_trash(message.get('doi')):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "条目已成功从垃圾箱恢复"}
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
    

# 检查指定 DOI 的条目是否从垃圾箱中恢复
def check_item_restored_from_trash(doi):
    conn = None  # 初始化 conn 变量，确保它总是有定义
    temp_db_path = None
    
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
        
        # 连接到临时数据库副本
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        
        # 1. 找到 DOI 字段的 fieldID
        cursor.execute("SELECT fieldID FROM fields WHERE fieldName = 'DOI'")
        doi_field_id = cursor.fetchone()
        
        if not doi_field_id:
            print("未找到 DOI 字段")
            return False
        
        doi_field_id = doi_field_id[0]
        
        # 2. 找到具有指定 DOI 的条目
        cursor.execute("""
            SELECT items.itemID, items.key, items.libraryID
            FROM items 
            JOIN itemData ON items.itemID = itemData.itemID 
            JOIN itemDataValues ON itemData.valueID = itemDataValues.valueID 
            WHERE itemData.fieldID = ? AND itemDataValues.value = ?
        """, (doi_field_id, doi))
        
        item = cursor.fetchone()
        
        if not item:
            print(f"未找到 DOI 为 {doi} 的条目")
            return False
        
        item_id = item[0]
        item_key = item[1]
        library_id = item[2]
        print(f"找到条目 ID: {item_id}, Key: {item_key}, 库 ID: {library_id}, DOI: {doi}")
        
        # 3. 检查条目是否在 deletedItems 表中
        cursor.execute("""
            SELECT COUNT(*) FROM deletedItems 
            WHERE itemID = ?
        """, (item_id,))
        
        is_in_trash = cursor.fetchone()[0] > 0
        
        if is_in_trash:
            print(f"条目 ID: {item_id} 当前在垃圾箱中")
            return False  # 如果在垃圾箱中，则未恢复
        
        # 简化逻辑：条目有效且不在垃圾箱，则认为已恢复
        print(f"条目 ID: {item_id} 有效且不在垃圾箱中，视为已恢复")
        return True
        
    except sqlite3.Error as e:
        print(f"查询数据库时出错: {e}")
        return False
    
    except Exception as e:
        print(f"检查条目恢复状态时出错: {e}")
        return False
        
    finally:
        # 无论查询是否成功，都关闭连接并删除临时数据库
        if conn:
            try:
                conn.close()
            except sqlite3.Error as e:
                print(f"关闭数据库连接时出错: {e}")
        
        if temp_db_path and os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
                print(f"已删除临时数据库副本")
            except OSError as e:
                print(f"删除临时数据库时出错: {e}")