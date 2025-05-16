import os
import json
import time
from typing import Dict, Any, Optional, List
import shutil
import sqlite3
import platform
import re


def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    event_type = message.get('event_type')
    if event_type == 'github_url_note_added':
        # TODO: 这里的tag能生成出来其实就可以了，对其内容的检查是后续延申的步骤
        if items_with_title_contain_github_repo(message.get('item_id')):
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": "条目已成功添加 GitHub 仓库链接"}
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



# 检查包含特定字符串的题目的条目是否有包含 GitHub 仓库链接的笔记
def items_with_title_contain_github_repo(title_search_str) -> bool:
    """
    检查标题包含特定字符串的条目是否有笔记包含 GitHub 仓库链接
    
    参数:
        title_search_str: 要在标题中搜索的字符串
    
    返回:
        是否有符合条件的条目 (bool)
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
        
        # 查找标题包含特定字符串的条目
        cursor.execute("""
            SELECT i.itemID, f.fieldName, iv.value
            FROM items i
            JOIN itemData id ON i.itemID = id.itemID
            JOIN fields f ON id.fieldID = f.fieldID
            JOIN itemDataValues iv ON id.valueID = iv.valueID
            WHERE f.fieldName = 'title' AND iv.value LIKE ?
        """, (f"%{title_search_str}%",))
        
        matching_items = cursor.fetchall()
        
        if not matching_items:
            print(f"未找到标题包含 '{title_search_str}' 的条目")
            return False
        
        print(f"找到 {len(matching_items)} 个标题包含 '{title_search_str}' 的条目")
        
        # GitHub 仓库链接的正则表达式模式
        github_repo_pattern = re.compile(r'(https?://)?(www\.)?github\.com/[\w.-]+/[\w.-]+')
        
        # 检查每个匹配条目的笔记
        for item_id, _, title in matching_items:
            # 查找与该条目关联的所有笔记
            cursor.execute("""
                SELECT n.itemID, n.note
                FROM itemNotes n
                WHERE n.parentItemID = ?
            """, (item_id,))
            
            notes = cursor.fetchall()
            
            if not notes:
                print(f"条目 '{title}' (ID: {item_id}) 没有任何笔记")
                continue
            
            # 检查笔记中是否包含 GitHub 链接
            found_repos = []
            
            for note_id, note_content in notes:
                if not note_content:
                    continue
                
                # 查找 GitHub 仓库链接
                matches = github_repo_pattern.findall(note_content)
                
                if matches:
                    # 重新构建完整的 URL
                    full_matches = re.findall(r'(?:https?://)?(?:www\.)?github\.com/[\w.-]+/[\w.-]+', note_content)
                    found_repos.extend(full_matches)
            
            # 如果找到任何仓库链接，立即返回 True
            if found_repos:
                print(f"条目 '{title}' (ID: {item_id}) 的笔记中找到以下 GitHub 仓库链接:")
                for repo in found_repos:
                    print(f"  - {repo}")
                return True
        
        # 如果检查完所有匹配的条目都没有找到 GitHub 仓库链接
        print(f"所有标题包含 '{title_search_str}' 的条目中，均未找到包含 GitHub 仓库链接的笔记")
        return False
    
    except sqlite3.Error as e:
        print(f"查询数据库时出错: {e}")
        return False
    
    except Exception as e:
        print(f"处理过程中出错: {e}")
        return False
    
    finally:
        # 关闭数据库连接
        if conn:
            conn.close()
        
        # 删除临时数据库
        if temp_db_path and os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
                print(f"已删除临时数据库副本")
            except OSError as e:
                print(f"删除临时数据库时出错: {e}")