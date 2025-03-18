from typing import Dict, Any 
import os
import time
import json

from evaluator.core.hook_manager import HookManager
from evaluator.core.result_collector import ResultCollector
from evaluator.utils.logger import setup_logger

class BaseEvaluator:
    """
    评估器基类，定义通用的评估流程和接口，可被特定任务评估器继承和扩展
    """
    
    def __init__(self, task: Dict, log_dir: str = "logs", app_path: str = None):
        """
        初始化基础评估器
        
        Args:
            task_id: 任务唯一标识
            log_dir: 日志和结果保存目录
        """
        self.task_category = task['category']
        self.task_id = task['id']
        self.log_dir = log_dir
        self.session_id = time.strftime("%Y%m%d_%H%M%S")
        self.session_dir = os.path.join(log_dir, self.session_id)
        self.app_path = app_path
        
        # 创建会话目录
        os.makedirs(self.session_dir, exist_ok=True)
        
        # 设置日志记录器
        self.logger = setup_logger(f"{self.task_category}_{self.task_id}_evaluator", self.session_dir)
        
        # 初始化组件，传入统一的logger
        self.hook_manager = HookManager(logger=self.logger)
        self.hook_manager.add_script(os.path.join(self.task_category, self.task_id))
        self.set_message_handler(os.path.join(self.task_category, self.task_id))
            
        self.result_collector = ResultCollector(self.session_dir, logger=self.logger)
        
        # 评估状态
        self.is_running = False
        self.task_completed = False
        self.start_time = None
        self.end_time = None
        
        # 评估配置和结果
        self.config = {}
        self.metrics = {}
        
        self.logger.info(f"评估器初始化完成: {self.task_id}")
    
    def record_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        记录事件
        
        Args:
            event_type: 事件类型
            data: 事件数据
        """
        event_data = {
            "type": event_type,
            "data": data,
            "timestamp": time.time()
        }
        self.result_collector.add_event(self.task_id, event_data)
        self.logger.debug(f"记录事件: {event_type} - {data}")
        
    def set_message_handler(self, task_id: str) -> None:
        # 尝试导入对应的handler模块
        try:
            handler_path = os.path.join("tests/tasks", task_id, "handler.py")
            if os.path.exists(handler_path):
                # 构建模块路径
                module_path = f"tests.tasks.{task_id.replace('/', '.')}.handler"
                self.logger.info(f"尝试导入回调函数模块: {module_path}")
                
                # 动态导入模块
                import importlib
                handler_module = importlib.import_module(module_path)
                
                # 检查模块中是否有message_handler函数
                if hasattr(handler_module, 'register_handlers'):
                    self.message_handler = handler_module.register_handlers(self)
                    self.logger.info(f"成功设置回调函数: {module_path}.message_handler")
                else:
                    self.logger.warning(f"未找到回调函数: {module_path}")
            else:
                self.logger.warning(f"回调函数文件不存在: {handler_path}")
        except Exception as e:
            self.logger.error(f"导入回调函数模块失败: {str(e)}")
            
    def _on_message(self, message: Dict[str, Any], data: Any) -> None:
        """
        内部消息处理函数
        
        Args:
            message: 消息对象
            data: 附加数据
        """
        if self.message_handler:
            result = self.message_handler(message, data)
            if result == "success":
                self.task_completed = True
    
    def update_metric(self, metric_name: str, value: Any) -> None:
        """
        更新评估指标
        
        Args:
            metric_name: 指标名称
            value: 指标值
        """
        self.metrics[metric_name] = value
        self.result_collector.update_metrics(self.task_id, {metric_name: value})
        self.logger.info(f"更新指标: {metric_name} = {value}")
    
    def start(self, **kwargs) -> bool:
        """
        启动评估
        
        Returns:
            bool: 启动是否成功
        """
        if self.is_running:
            self.logger.warning("评估器已经在运行")
            return False
        
        try:
            self.start_time = time.time()
            self.is_running = True
            
            # 如果提供了应用路径，则启动应用
            if self.app_path and os.path.exists(self.app_path):
                try:
                    import subprocess
                    self.logger.info(f"正在启动应用: {self.app_path}")
                    # 使用子进程启动应用
                    self.app_process = subprocess.Popen([self.app_path], 
                                                       stdout=subprocess.PIPE,
                                                       stderr=subprocess.PIPE)
                    self.logger.info(f"应用启动成功，进程ID: {self.app_process.pid}")
                    
                    # 等待应用窗口加载完成
                    self.logger.info("等待应用窗口加载完成...")
                    
                    # Linux系统：使用xwininfo命令检测窗口变化
                    try:
                        # 获取启动前窗口列表
                        windows_before = subprocess.run(["xwininfo", "-root", "-tree"], 
                                                    stdout=subprocess.PIPE, 
                                                    text=True).stdout.count('\n')
                        self.logger.info(f"启动前窗口行数: {windows_before}")
                        
                        # 等待新窗口出现
                        max_wait_time = 30  # 最大等待30秒
                        start_wait = time.time()
                        window_detected = False
                        
                        while time.time() - start_wait < max_wait_time:
                            windows_current = subprocess.run(["xwininfo", "-root", "-tree"], 
                                                        stdout=subprocess.PIPE, 
                                                        text=True).stdout.count('\n')
                            if windows_current > windows_before:
                                window_detected = True
                                self.logger.info(f"检测到新窗口，当前窗口行数: {windows_current}")
                                # 额外等待2秒确保窗口内容加载完成
                                time.sleep(2)
                                break
                            time.sleep(0.5)
                        
                        if not window_detected:
                            self.logger.warning("未检测到新窗口出现，使用默认等待时间")
                            time.sleep(5)
                    except Exception as window_error:
                        self.logger.warning(f"窗口检测出错: {str(window_error)}，使用默认等待时间")
                        time.sleep(5)
                except Exception as e:
                    self.logger.error(f"应用启动失败: {str(e)}")
            elif self.app_path:
                self.logger.error(f"应用路径不存在: {self.app_path}")
            
            self.hook_manager.load_scripts(self.app_process.pid, self._on_message)
            self.result_collector.start_session(self.task_id, {
                "start_time": self.start_time,
                "config": self.config,
                "app_path": self.app_path
            })
            self.logger.info("评估器启动成功")
            
            return True
        except Exception as e:
            self.logger.error(f"评估器启动失败: {str(e)}")
            return False
    
    def stop(self) -> None:
        """
        停止评估
        """
        if not self.is_running:
            self.logger.warning("评估器未运行")
            return
        
        try:
            # 卸载钩子脚本
            self.hook_manager.unload_scripts()
            # 停止应用进程
            if hasattr(self, 'app_process') and self.app_process:
                try:
                    self.logger.info(f"正在终止应用进程 (PID: {self.app_process.pid})")
                    self.app_process.terminate()
                    # 给进程一些时间来正常终止
                    self.app_process.wait(timeout=5)
                    self.logger.info("应用进程已正常终止")
                except Exception as e:
                    self.logger.warning(f"终止应用进程时出错: {str(e)}")
                    try:
                        # 如果正常终止失败，强制终止进程
                        self.app_process.kill()
                        self.logger.info("应用进程已强制终止")
                    except Exception as kill_error:
                        self.logger.error(f"强制终止应用进程失败: {str(kill_error)}")
            
            self.end_time = time.time()
            duration = self.end_time - self.start_time
            
            self.update_metric("duration", duration)
            self.is_running = False
            
            self.result_collector.end_session(self.task_id, {
                "end_time": self.end_time,
                "duration": duration,
                "metrics": self.metrics
            })
            
            self.save_results()
            self.logger.info(f"评估器已停止，总耗时: {duration:.2f}秒")
        except Exception as e:
            self.logger.error(f"评估器停止失败: {str(e)}")
    
    def save_results(self) -> str:
        """
        保存评估结果
        
        Returns:
            str: 结果文件路径
        """
        results_path = self.result_collector.save_results(self.task_id)
        self.logger.info(f"评估结果已保存: {results_path}")
        return results_path
    
    def generate_report(self) -> str:
        """
        生成评估报告
        
        Returns:
            str: 报告文件路径
        """
        # 基类提供基础报告生成，子类可重写以提供更详细的报告
        report_path = os.path.join(self.session_dir, f"{self.task_id}_report.md")
        
        results = self.result_collector.get_results(self.task_id)
        
        # 基本报告模板
        report_content = f"""# {self.task_id} 评估报告

## 基本信息
- 任务ID: {self.task_id}
- 会话ID: {self.session_id}
- 开始时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_time or 0))}
- 结束时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.end_time or 0))}
- 总耗时: {results.get('duration', 0):.2f} 秒

## 评估指标
"""
        # 添加指标
        for name, value in self.metrics.items():
            report_content += f"- {name}: {value}\n"
        
        # 添加事件日志
        report_content += "\n## 事件日志\n"
        events = results.get("events", [])
        for event in events:
            event_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event['timestamp']))
            report_content += f"- [{event_time}] {event['type']}: {json.dumps(event['data'])}\n"
        
        # 写入报告文件
        with open(report_path, 'w') as f:
            f.write(report_content)
        
        self.logger.info(f"评估报告已生成: {report_path}")
        return report_path