from typing import Dict, Any, List
import os
import sys
import time
import json
import signal
import subprocess
import time
from string import Template

# TODO 能不能只读入一个基类，然后根据不同的任务类型，自动选择不同的hook_manager？
from evaluator.core.hook_manager import HookManager
from evaluator.core.ipc_injector import IpcInjector
from evaluator.core.state_inspector import StateInspector

from evaluator.core.result_collector import ResultCollector
from evaluator.utils.logger import setup_logger

class EventType:
    TASK_COMPLETED = "task_completed"
    TASK_ERROR = "task_error"
    TASK_PROGRESS = "task_progress"
    EVALUATOR_STOPPED = "evaluator_stopped"

class EventData:
    def __init__(self, event_type: str, message: str, data: Dict[str, Any] = None):
        self.event_type = event_type
        self.message = message
        self.data = data or {}

class BaseEvaluator:
    """
    评估器基类，定义通用的评估流程和接口，可被特定任务评估器继承和扩展
    """

    def __init__(self, task: Dict, log_dir: str = "logs", app_path: str = None, custom_params: Dict = None, **kwargs):
        """
        初始化基础评估器
        
        Args:
            task: 任务配置字典
            log_dir: 日志和结果保存目录
            app_path: 应用程序路径
            custom_params: 自定义参数字典，可用于覆盖或补充配置中的参数
            **kwargs: 其他参数
        """
        self.task_category = task['category']
        self.task_id = task['id']
        self.log_dir = log_dir
        self.session_id = time.strftime("%Y%m%d_%H%M%S")
        self.session_dir = os.path.join(log_dir, self.session_id)
        # TODO app 状态的相关的信息是否全部移到hook_manager中？
        self.app_started = False

        # 保存自定义参数
        self.custom_params = custom_params or {}

        # 创建会话目录
        os.makedirs(self.session_dir, exist_ok=True)

        # 设置日志记录器
        self.logger = setup_logger(f"{self.task_category}_{self.task_id}_evaluator", self.session_dir)
        FILE_ROOT = os.path.dirname(os.path.abspath(__file__))
        CANARY_ROOT = os.path.dirname(os.path.dirname(FILE_ROOT))
        self.task_path = os.path.join(CANARY_ROOT, "tests/tasks", self.task_category, self.task_id)

        # 评估状态
        self.is_running = False
        self.task_completed = False
        # 评估配置和结果
        self.config = {}
        self.metrics = {}

        # 回调相关
        self.completion_callbacks = []

        # 读取配置文件并初始化 self.instruction
        config_path = os.path.join(self.task_path, "config.json")
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as config_file:
                self.config = json.load(config_file)
                # 使用 custom_params 覆盖或补充配置
                if self.custom_params:
                    # 如果有task_parameters参数，特殊处理
                    if 'task_parameters' in self.config and 'task_parameters' in self.custom_params:
                        # 只更新已存在的键的值，不添加新键
                        for key, value in self.custom_params['task_parameters'].items():
                            if key in self.config['task_parameters']:
                                # 记录更新
                                old_value = self.config['task_parameters'][key]
                                self.config['task_parameters'][key] = value
                                self.logger.info(f"更新任务参数: {key} = {value} (原值: {old_value})")
                            else:
                                # 记录被忽略的未知参数
                                self.logger.warning(f"忽略未知的任务参数: {key} = {value}")

                    # 对于其他任何顶级参数，直接覆盖
                    for key, value in self.custom_params.items():
                        if key != 'task_parameters':  # task_parameters已特殊处理
                            self.config[key] = value
                            self.logger.info(f"已使用自定义参数设置: {key}={value}")

                # Load and render instruction template with parameters
                raw_template = self.config.get('instruction_template', self.config.get('instruction', ''))
                params = self.config.get('task_parameters', {})
                try:
                    self.instruction = Template(raw_template).safe_substitute(params)
                except Exception as e:
                    self.logger.warning(f"Instruction template substitution failed: {e}")
                    self.instruction = raw_template
                self.logger.info(f"加载任务指令: {self.instruction}")
        else:
            self.logger.warning(f"配置文件不存在: {config_path}")

        self.preconditions = self.config.get("preconditions", {})
        self.success_conditions = set(self.config.get("success_conditions", []))
        self.timeout = self.config.get("evaluation_setup", {}).get("timeout", 180)
        evaluate_on_completion = self.config.get("evaluation_setup", {}).get("evaluate_on_completion", False)
        evaluator_type = self.config.get("evaluation_setup", {}).get("evaluator_type", "HookManager")
        launch_args = self.config.get("application_info", {}).get("args", [])
        # 初始化组件，传入统一的logger
        if evaluator_type == "IpcInjector":
            self.hook_manager = IpcInjector(
                app_path=app_path,
                args=launch_args,
                logger=self.logger,
                evaluate_on_completion=evaluate_on_completion
            )
        elif evaluator_type == "StateInspector":
            self.hook_manager = StateInspector(
                app_path=app_path,
                args=launch_args,
                logger=self.logger,
                evaluate_on_completion=evaluate_on_completion
            )
        else:
            self.hook_manager = HookManager(
                app_path=app_path,
                args=launch_args,
                logger=self.logger,
                evaluate_on_completion=evaluate_on_completion
            )
        self.hook_manager.add_script(self.task_path)
        self.set_message_handler()
        self.result_collector = ResultCollector(self.session_dir, logger=self.logger)
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

    def set_message_handler(self) -> None:
        # 尝试导入对应的handler模块
        try:
            handler_path = self.task_path
            if os.path.exists(handler_path):
                # 构建模块路径
                module_path = f"tests.tasks.{self.task_category}.{self.task_id}.handler"
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
                event_data = EventData(EventType.TASK_COMPLETED, "Task completed successfully")
                self._trigger_completion_callbacks(event_data)
            elif result == "error":
                event_data = EventData(EventType.TASK_ERROR, f"Task error: {message.get('error', 'unknown error')}")
                self._trigger_completion_callbacks(event_data)
            elif result == "progress":
                self.logger.info(f"Task progress: {message.get('progress', '0')}%")
                # Optionally handle progress updates

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

    def register_completion_callback(self, callback) -> None:
        """
        注册任务完成时的回调函数
        
        Args:
            callback: 回调函数，接收任务完成状态、结果和指标作为参数
        """
        self.completion_callbacks.append(callback)
        self.logger.info("注册了新的完成回调函数")

    def _trigger_completion_callbacks(self, event_data: EventData) -> None:
        """
        触发所有注册的完成回调函数
        
        Args:
            event_data: 事件数据
        """
        self.logger.info(f"Event: {event_data.event_type} - {event_data.message}")
        for callback in self.completion_callbacks:
            try:
                callback(event_data, self)
            except Exception as e:
                self.logger.error(f"Error executing callback: {str(e)}")

    def start(self) -> bool:
        """
        启动评估
            
        Returns:
            bool: 启动是否成功
        """
        if self.is_running:
            self.logger.warning("评估器已经在运行")
            return False

        if not self.app_started:
            self.start_app()

        try:
            self.is_running = True
            self.hook_manager.load_scripts(self._on_message)
            self.result_collector.start_session(self.task_id, {
                "config": self.config,
                "app_path": self.hook_manager.app_path,
                "app_process_pid": self.hook_manager.app_process.pid
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
            # 先设置is_running, 避免死循环
            self.is_running = False
            # 卸载钩子脚本
            self.hook_manager.unload_scripts()

            self.result_collector.end_session(self.task_id, {
                "metrics": self.metrics
            })

            # 如果尚未触发完成回调，则在停止时触发
            if not self.task_completed:
                self._trigger_completion_callbacks(EventData(EventType.EVALUATOR_STOPPED, "evaluator stopped"))

            self.save_results()
        except Exception as e:
            self.logger.error(f"评估器停止失败: {str(e)}")

    def start_app(self) -> bool:
        #  如果提供了应用路径，则启动应用
        return self.hook_manager.start_app()

    def stop_app(self) -> None:
        # 停止应用进程
        return self.hook_manager.stop_app()

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
