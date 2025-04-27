from .hook_manager import HookManager
from typing import List, Dict, Any, Optional, Callable
import logging
import os
import importlib

class StateInspector(HookManager):
    """
    基于REST API或app库实现的任务评估器, 负责加载评估脚本, 评估脚本负责和服务器通信等功能
    
    本评估方式是没有必要处理各种异步事件的
    """
    def __init__(self, app_path: str = None, args: List[str] = None, logger: Optional[logging.Logger] = None, evaluate_on_completion: bool = False):
        super().__init__(app_path, args, logger, evaluate_on_completion)
        self.inspector_on_start = []
        self.inspector_on_completion = []
        self.eval_handler = None

    def add_script(self, task_path: str) -> None:
        # 目前选择的APP库基本是python实现
        hooker_path = os.path.join(task_path, "hooker.py")
        if os.path.exists(hooker_path):
            self.scripts.append(hooker_path)
            self.logger.info(f"添加钩子脚本: {hooker_path}")
        else:
            self.logger.error(f"脚本文件不存在: {hooker_path}")

    def load_scripts(self, eval_handler: Callable[[Dict[str, Any], Any], None]) -> bool:
        self.eval_handler = eval_handler
        if not self.scripts:
            self.logger.warning("没有脚本可加载")
            return False

        # 加载所有脚本
        for script_path in self.scripts:
            try:
                module_path = '.'.join(script_path.split("/")[-5:-1]+['hooker'])
                script_module = importlib.import_module(module_path)
                if hasattr(script_module, 'inspector_on_start'):
                    self.inspector_on_start.append(script_module.inspector_on_start)
                    # 获取app初始状态
                    script_module.inspector_on_start()
                if hasattr(script_module, 'inspector_on_completion'):
                    self.inspector_on_completion.append(script_module.inspector_on_completion)
                self.loaded_scripts.append(script_path)
                self.logger.info(f"加载脚本成功: {script_path}")
            except Exception as e:
                self.logger.error(f"加载脚本失败 {script_path}: {str(e)}")
        return len(self.loaded_scripts) > 0

    def unload_scripts(self) -> None:
        if self.evaluate_on_completion:
            self.trigger_evaluate_on_completion()
        self.inspector_on_completion.clear()
        self.inspector_on_start.clear()
        self.eval_handler = None
        self.loaded_scripts.clear()
    
    def start_app(self) -> bool:
        return super().start_app()
    
    def stop_app(self) -> None:
        return super().stop_app()
    
    def trigger_evaluate_on_completion(self) -> None:
        self.logger.info("在任务操作完毕时触发评估")
        try:
            for f in self.inspector_on_completion:
                f(self.eval_handler)
        except Exception as e:
            self.logger.error(f"在任务结束时评估触发错误: {str(e)}")
