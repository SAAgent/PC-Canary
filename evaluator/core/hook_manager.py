from typing import List, Dict, Any, Optional, Callable
import os
import frida
import logging

class HookManager:
    """
    钩子管理器，负责加载和管理Frida脚本
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        初始化钩子管理器
        
        Args:
            logger: 日志记录器，如果为None则使用默认记录器
        """
        self.scripts = []  # 脚本路径列表
        self.frida_session = None  # Frida会话
        self.loaded_scripts = []  # 已加载的脚本对象
        self.message_handler = None  # 消息处理函数
        self.logger = logger
    
    def add_script(self, task_id: str) -> None:
        """
        添加钩子脚本
        
        Args:
            task_id: 脚本路径
        """
        hooker_path = os.path.join("tests/tasks", task_id, "hooker.js")
        if os.path.exists(hooker_path):
            self.scripts.append(hooker_path)
            self.logger.info(f"添加钩子脚本: {hooker_path}")
        else:
            self.logger.error(f"脚本文件不存在: {hooker_path}")
    
    
    def load_scripts(self, target_process: str, eval_handler: Callable[[Dict[str, Any], Any], None]) -> bool:
        """
        加载脚本到目标进程
        
        Args:
            target_process: 目标进程名称或ID
            
        Returns:
            bool: 加载是否成功
        """
        if not self.scripts:
            self.logger.warning("没有脚本可加载")
            return False
        
        try:
            # 连接到目标进程
            self.logger.info(f"连接到进程: {target_process}")
            self.frida_session = frida.attach(target_process)
            
            # 加载所有脚本
            for script_path in self.scripts:
                try:
                    with open(script_path, 'r') as f:
                        script_content = f.read()
                    
                    script = self.frida_session.create_script(script_content)
                    script.on('message', eval_handler)
                    script.load()
                    
                    self.loaded_scripts.append(script)
                    self.logger.info(f"加载脚本成功: {script_path}")
                except Exception as e:
                    self.logger.error(f"加载脚本失败 {script_path}: {str(e)}")
            
            return len(self.loaded_scripts) > 0
        
        except frida.ProcessNotFoundError:
            self.logger.error(f"未找到进程: {target_process}")
            return False
        except Exception as e:
            self.logger.error(f"连接到进程失败: {str(e)}")
            return False
    
    def unload_scripts(self) -> None:
        """
        卸载所有脚本
        """
        try:
            for script in self.loaded_scripts:
                script.unload()
            
            self.loaded_scripts = []
            
            if self.frida_session:
                self.frida_session.detach()
                self.frida_session = None
            
            self.logger.info("脚本卸载完成")
        except Exception as e:
            self.logger.error(f"卸载脚本失败: {str(e)}")