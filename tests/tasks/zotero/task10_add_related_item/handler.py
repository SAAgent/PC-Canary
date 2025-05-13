import os
import json
import time
from typing import Dict, Any, Optional, List
import shutil
import sqlite3
import platform

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    if event_type == 'related_item_added':
        if has_related_items(message.get('doi')):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "条目已成功添加相关条目"}
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
    
    
# 检查指定 DOI 的条目是否有相关条目（基于正确的表结构）
def has_related_items(doi):
    """
    检查特定 DOI 的条目是否有相关条目
    
    参数:
        doi (str): 条目的 DOI
        
    返回:
        bool: 如果条目存在且有相关条目则返回 True；否则返回 False
    """
    conn = None
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
            SELECT items.itemID, items.key
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
        print(f"找到条目 ID: {item_id}, Key: {item_key}, DOI: {doi}")
        
        # 3. 检查 itemRelations 表，查看是否有与该条目相关的关系
        # 基于正确的表结构：itemID, predicateID, object
        
        # 检查条目作为 itemID 的关系（该条目指向其他对象）
        cursor.execute("""
            SELECT COUNT(*) FROM itemRelations 
            WHERE itemID = ?
        """, (item_id,))
        
        outgoing_count = cursor.fetchone()[0]
        
        # 检查条目作为 object 的关系（其他条目指向该条目）
        # 对于 object 字段，我们需要查找包含该条目键的对象
        # 通常 object 可能包含 URI 格式的项目键，如 "http://zotero.org/users/1234/items/ABCDEFGH"
        cursor.execute("""
            SELECT COUNT(*) FROM itemRelations 
            WHERE object LIKE '%' || ? || '%'
        """, (item_key,))
        
        incoming_count = cursor.fetchone()[0]
        
        # 如果存在任何关系，则返回 True
        total_relations = outgoing_count + incoming_count
        
        if total_relations > 0:
            print(f"条目 ID: {item_id} 有 {total_relations} 个相关条目关系 ({outgoing_count} 个外向, {incoming_count} 个传入)")
            return True
        else:
            print(f"条目 ID: {item_id} 没有相关条目")
            return False
        
    except sqlite3.Error as e:
        print(f"查询数据库时出错: {e}")
        return False
    
    except Exception as e:
        print(f"检查条目关系时出错: {e}")
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