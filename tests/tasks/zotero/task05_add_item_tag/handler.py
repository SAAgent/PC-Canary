import os
import json
import time
from typing import Dict, Any, Optional, List
import shutil
import sqlite3
import platform


def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    if event_type == 'item_tag_added':
        if check_tag_for_doi(message.get('doi'), message.get('tag')):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "标签已成功添加"}
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

# 检查指定 DOI 的条目是否有特定标签
def check_tag_for_doi(doi, tag_name):
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
            
            # 1. 首先找到 DOI 字段的 fieldID
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
            
            # 3. 查找该条目是否有指定标签
            # 在 Zotero 中，标签存储在 tags 表中，通过 itemTags 表与条目关联
            cursor.execute("""
                SELECT tags.name 
                FROM itemTags 
                JOIN tags ON itemTags.tagID = tags.tagID 
                WHERE itemTags.itemID = ? AND tags.name LIKE ?
            """, (item_id, f"%{tag_name}%"))
            
            tags = cursor.fetchall()
            print(f"查询到的标签: {tags}")
            
            conn.close()
            
            if tags:
                for tag in tags:
                    print(f"条目包含标签: {tag[0]}")
                return True
            else:
                print(f"DOI 为 {doi} 的条目不包含标签 '{tag_name}'")
                return False
            
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
        print(f"检查标签时出错: {e}")
        return False