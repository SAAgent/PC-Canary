import os
import json
import time
from typing import Dict, Any, Optional, List
import shutil
import sqlite3
import platform

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    # TODO: 这里可能需要一个item一个item的处理
    if event_type == 'moved_items_by_tag':
        if check_collection_contains_all_dois(message.get('collection_name'), message.get('required_dois')):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "条目已成功移动到指定的 collection"}
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

# 检查给定 collection 是否包含所有指定的 DOI
def check_collection_contains_all_dois(collection_name, required_dois) -> bool:
    """
    检查指定的 collection 是否包含所有给定的 DOI
    
    参数:
        collection_name: Zotero collection 的名称
        required_dois: 需要检查的 DOI 集合
        
    返回:
        是否包含所有 DOI (bool)
    """
    conn = None  # 在 try 块外初始化连接变量
    temp_db_path = None  # 初始化临时文件路径
    
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
        
        # 找到指定 collection 的 ID
        cursor.execute("""
            SELECT collectionID 
            FROM collections 
            WHERE collectionName = ?
        """, (collection_name,))
        
        result = cursor.fetchone()
        
        if not result:
            print(f"未找到名为 '{collection_name}' 的 collection")
            return False
        
        collection_id = result[0]
        
        # 查找该 collection 中的所有 item
        cursor.execute("""
            SELECT i.itemID
            FROM items i
            JOIN collectionItems ci ON i.itemID = ci.itemID
            WHERE ci.collectionID = ? AND i.itemTypeID NOT IN (1, 14)
        """, (collection_id,))
        
        item_ids = [row[0] for row in cursor.fetchall()]
        
        if not item_ids:
            print(f"Collection '{collection_name}' 中没有找到任何项目")
            return False
        
        # 查找这些 item 的 DOI
        found_dois = set()
        for item_id in item_ids:
            cursor.execute("""
                SELECT value
                FROM itemData id
                JOIN itemDataValues idv ON id.valueID = idv.valueID
                JOIN fields f ON id.fieldID = f.fieldID
                WHERE id.itemID = ? AND f.fieldName = 'DOI'
            """, (item_id,))
            
            doi_result = cursor.fetchone()
            if doi_result and doi_result[0]:
                found_dois.add(doi_result[0].lower().strip())
        
        # 将指定的 DOI 转为小写以进行大小写不敏感的比较
        normalized_required_dois = {doi.lower().strip() for doi in required_dois}
        
        # 找出在集合中缺失的 DOI
        missing_dois = normalized_required_dois - found_dois
        
        # 找出存在的 DOI
        existing_dois = normalized_required_dois.intersection(found_dois)
        
        # 检查是否包含所有需要的 DOI
        contains_all = len(missing_dois) == 0
        
        print(f"Collection '{collection_name}' 中找到 {len(existing_dois)}/{len(normalized_required_dois)} 个指定的 DOI")
        
        if not contains_all:
            print(f"缺少以下 DOI: {missing_dois}")
        else:
            print(f"包含所有指定的 DOI")
        
        print(f"找到的 DOI: {existing_dois}")
        
        return contains_all
        
    except sqlite3.Error as e:
        print(f"查询数据库时出错: {e}")
        return False
    
    except Exception as e:
        print(f"检查 DOI 时出错: {e}")
        return False
        
    finally:
        # 关闭数据库连接
        if conn:
            conn.close()
        
        # 无论查询是否成功，都删除临时数据库
        if temp_db_path and os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
                print(f"已删除临时数据库副本")
            except OSError as e:
                print(f"删除临时数据库时出错: {e}")