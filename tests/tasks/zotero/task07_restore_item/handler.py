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
    if event_type == 'item_restored':
        _EVALUATOR.update_metric("success", True)
    else:
        _EVALUATOR.update_metric("error", {"type": "unknown", "message": "未知错误"})

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
        
        # 4. 检查同步对象类型表以获取 item 类型的 ID
        cursor.execute("""
            SELECT syncObjectTypeID FROM syncObjectTypes 
            WHERE name = 'item'
        """)
        
        sync_object_type_id = cursor.fetchone()
        
        if not sync_object_type_id:
            print("未找到 'item' 的同步对象类型 ID")
            return False
        
        sync_object_type_id = sync_object_type_id[0]
        
        # 5. 检查 syncDeleteLog 表中是否有该条目的删除记录
        cursor.execute("""
            SELECT COUNT(*) FROM syncDeleteLog 
            WHERE syncObjectTypeID = ? AND libraryID = ? AND key = ?
        """, (sync_object_type_id, library_id, item_key))
        
        has_delete_log = cursor.fetchone()[0] > 0
        
        if has_delete_log:
            # 条目在 syncDeleteLog 中有记录但不在 deletedItems 中
            # 这说明它可能曾经被删除但已经恢复
            print(f"条目在 syncDeleteLog 表中有记录，但不在 deletedItems 表中，表明它可能曾被删除后恢复")
            
            # 获取删除记录详情
            cursor.execute("""
                SELECT dateDeleted FROM syncDeleteLog 
                WHERE syncObjectTypeID = ? AND libraryID = ? AND key = ?
                ORDER BY dateDeleted DESC
            """, (sync_object_type_id, library_id, item_key))
            
            delete_dates = cursor.fetchall()
            
            if delete_dates:
                print("删除日期记录:")
                for date in delete_dates:
                    print(f"  - {date[0]}")
            
            return True
        else:
            print("条目在 syncDeleteLog 表中无记录，表明它可能从未被删除过")
            return False
        
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