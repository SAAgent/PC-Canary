import os
import json
import time
from typing import Dict, Any, Optional, Callable
import shutil
import sqlite3
import platform


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
    if event_type == 'item_to_collection_added':
        if check_item_in_collection(message.get('doi'), message.get('collection')):
            _EVALUATOR.update_metric("success", True)
            return "success"
    else:
        _EVALUATOR.update_metric("error", {"type": "unknown", "message": "未知错误"})
        return "error"

def register_handlers(evaluator):
    set_evaluator(evaluator)
    return message_handler

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
    
# 检查指定 DOI 的条目是否在特定分类中
def check_item_in_collection(doi, collection_name):
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
            
            # 3. 找到指定名称的分类
            cursor.execute("""
                SELECT collectionID, collectionName 
                FROM collections 
                WHERE collectionName LIKE ?
            """, (f"%{collection_name}%",))
            
            collections = cursor.fetchall()
            
            if not collections:
                print(f"未找到名称包含 '{collection_name}' 的分类")
                return False
            
            print(f"找到 {len(collections)} 个匹配的分类:")
            for coll in collections:
                print(f"  - 分类 ID: {coll[0]}, 名称: '{coll[1]}'")
            
            # 4. 检查条目是否在任何匹配的分类中
            for coll in collections:
                collection_id = coll[0]
                
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM collectionItems 
                    WHERE collectionID = ? AND itemID = ?
                """, (collection_id, item_id))
                
                count = cursor.fetchone()[0]
                
                if count > 0:
                    print(f"条目在分类 '{coll[1]}' (ID: {collection_id}) 中")
                    conn.close()
                    return True
            
            print(f"条目不在任何匹配的分类中")
            conn.close()
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
        print(f"检查条目分类时出错: {e}")
        return False