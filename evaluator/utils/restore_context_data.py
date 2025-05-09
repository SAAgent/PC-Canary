import os
import subprocess

def restore_context_data(from_path: str, to_path: str) -> bool:
    """
    将from_path目录下的所有内容增量更新到to_path目录
    
    Args:
        from_path: 源目录路径
        to_path: 目标目录路径
        
    Returns:
        bool: 如果操作成功返回True，否则返回False
    """
    # 检查源路径是否存在
    if not os.path.exists(from_path):
        raise Exception(f"用户数据{from_path}不存在")
    # 创建目标目录
    os.makedirs(to_path, exist_ok=True)
    
    # 复制源目录内容到目标目录
    try:
        rsync_cmd = ["rsync", "-av", "--delete", f"{from_path}/", to_path]
        result = subprocess.run(
            rsync_cmd,
            check=True,  # 如果命令失败，抛出异常
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        raise Exception(f"增量更新过程中发生错误: {str(e.stderr)}")
    except Exception as e:
        raise Exception(f"增量更新过程中发生错误: {str(e)}")
