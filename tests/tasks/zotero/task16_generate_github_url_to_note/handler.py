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
        if item_notes_contain_github_repo(message.get('item_id')):
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



# 检查指定 item 的 notes 中是否包含 GitHub 仓库链接
def item_notes_contain_github_repo(item_id) -> bool:
    """
    检查指定 item 的 notes 中是否包含 GitHub 仓库链接
    
    参数:
        item_id: Zotero item 的 ID
    
    返回:
        是否包含 GitHub 仓库链接 (bool)
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
        
        # 首先验证 item 是否存在
        cursor.execute("""
            SELECT itemID FROM items WHERE itemID = ?
        """, (item_id,))
        
        if not cursor.fetchone():
            print(f"未找到 ID 为 {item_id} 的 item")
            return False
        
        # 查找与该 item 关联的所有笔记
        cursor.execute("""
            SELECT n.itemID, n.note
            FROM itemNotes n
            WHERE n.parentItemID = ?
        """, (item_id,))
        
        notes = cursor.fetchall()
        
        if not notes:
            print(f"Item {item_id} 没有任何笔记")
            return False
        
        # GitHub 仓库链接的正则表达式模式
        # 匹配形如 https://github.com/username/repo 或 github.com/username/repo 的链接
        github_repo_pattern = re.compile(r'(https?://)?(www\.)?github\.com/[\w.-]+/[\w.-]+')
        
        # 检查每个笔记是否包含 GitHub 链接
        found_repos = []
        
        for note_id, note_content in notes:
            if not note_content:
                continue
                
            # 由于笔记可能是 HTML 格式，提取纯文本和链接
            matches = github_repo_pattern.findall(note_content)
            
            if matches:
                # 提取完整的匹配字符串
                full_matches = github_repo_pattern.findall(note_content)
                for match in full_matches:
                    # 如果匹配是元组(因为正则中有捕获组)，我们需要重新构造完整的 URL
                    if isinstance(match, tuple):
                        protocol = match[0] or "https://"  # 如果没有协议，默认使用 https://
                        www_part = match[1] or ""
                        # 实际的仓库 URL 是在原始文本中找到的，需要重新匹配
                        full_url = re.search(r'github\.com/[\w.-]+/[\w.-]+', note_content)
                        if full_url:
                            repo_url = protocol + www_part + full_url.group(0)
                            found_repos.append(repo_url)
                    else:
                        found_repos.append(match)
        
        # 检查是否找到任何仓库链接
        has_github_repos = len(found_repos) > 0
        
        if has_github_repos:
            print(f"Item {item_id} 的笔记中找到以下 GitHub 仓库链接:")
            for repo in found_repos:
                print(f"  - {repo}")
        else:
            print(f"Item {item_id} 的笔记中未找到 GitHub 仓库链接")
        
        return has_github_repos
    
    except sqlite3.Error as e:
        print(f"查询数据库时出错: {e}")
        return False
    
    except Exception as e:
        print(f"检查笔记时出错: {e}")
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