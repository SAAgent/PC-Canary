import os
import shutil

def restore_context_data(from_path: str, to_path: str) -> bool:
    """
    将from_path目录下的所有内容复制到to_path目录
    
    Args:
        from_path: 源目录路径
        to_path: 目标目录路径
        
    Returns:
        bool: 如果操作成功返回True，否则返回False
    """
    # 检查源路径是否存在
    if not os.path.exists(from_path):
        raise Exception(f"用户数据{from_path}不存在")

    # 如果目标路径存在，则清理其内容
    if os.path.exists(to_path):
        yes_or_no = input(f"需要删除{to_path}下的所有内容:(Y or N)")
        if yes_or_no == 'n' or yes_or_no == 'N':
            raise Exception(f"请重新设置{to_path}的路径")
        shutil.rmtree(to_path)
    
    # 创建目标目录
    os.makedirs(to_path, exist_ok=True)
    
    # 复制源目录内容到目标目录
    try:
        for item in os.listdir(from_path):
            src_item = os.path.join(from_path, item)
            dst_item = os.path.join(to_path, item)
            if os.path.isdir(src_item):
                shutil.copytree(src_item, dst_item)
            else:
                shutil.copy2(src_item, dst_item)
        return True
    except Exception as e:
        raise Exception(f"复制目录过程中发生错误: {str(e)}")
