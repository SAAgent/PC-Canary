import importlib
from typing import Dict, Any, List, Callable, Optional, Set
import os
import sys
import time
import json
import signal
import subprocess
import time
import logging
from string import Template

from evaluator.core.hook_manager import HookManager
from evaluator.core.ipc_injector import IpcInjector
from evaluator.core.state_inspector import StateInspector

from evaluator.core.result_collector import ResultCollector
from evaluator.core.events import AgentEvent
from evaluator.utils.logger import setup_logger
from evaluator.utils.restore_context_data import restore_context_data

# Data structure for completion callbacks
class CallbackEventData:
    def __init__(self, event_type: str, message: str, data: Dict[str, Any] = None):
        self.event_type = event_type # e.g., "task_completed", "task_error", "evaluator_stopped"
        self.message = message
        self.data = data or {}

class BaseEvaluator:
    """
    评估器基类，定义通用的评估流程和接口，可被特定任务评估器继承和扩展
    """

    def __init__(self, task: Dict, log_dir: str = "logs", app_path: str = None,
                app_working_path = None, custom_params: Dict = None, **kwargs):
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

        # 保存自定义参数
        self.custom_params = custom_params or {}

        # 创建会话目录
        os.makedirs(self.session_dir, exist_ok=True)

        # 设置日志记录器
        self.logger = setup_logger(f"{self.task_category}_{self.task_id}_evaluator", self.session_dir,level=logging.DEBUG)
        FILE_ROOT = os.path.dirname(os.path.abspath(__file__))
        self.canary_root = os.path.dirname(os.path.dirname(FILE_ROOT))
        self.task_path = os.path.join(self.canary_root, "tests/tasks", self.task_category, self.task_id)

        # 评估状态
        self.is_running = False
        self.task_completed = False
        # 评估配置和结果
        self.config = {}

        # 回调相关
        self.completion_callbacks: List[Callable[[CallbackEventData, 'BaseEvaluator'], None]] = []
        self._final_callback_triggered = False # Internal flag
        self.message_handler: Optional[Callable[[Dict, Any], Optional[List[Dict[str, Any]]]]] = None # Expect list of dicts

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

        # 初始化关键步骤信息 (总数即可，名称映射由 ResultCollector 处理)
        self.total_key_steps = self.config.get('total_key_steps', 0)


        self.preconditions = self.config.get("preconditions", {})
        self.timeout = self.config.get("evaluation_setup", {}).get("timeout", 180)
        evaluate_on_completion = self.config.get("evaluation_setup", {}).get("evaluate_on_completion", False)
        evaluator_type = self.config.get("evaluation_setup", {}).get("evaluator_type", "HookManager")
        launch_args = self.config.get("application_info", {}).get("args", [])
        app_working_cwd = self.config.get("application_info", {}).get("cwd", None)
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
                app_working_cwd=app_working_cwd,
                args=launch_args,
                logger=self.logger,
                evaluate_on_completion=evaluate_on_completion
            )

        # 初始化 ResultCollector (需要在 handler 设置前，以防 handler 访问)
        self.result_collector = ResultCollector(output_dir=self.session_dir, logger=self.logger)
        if not ("evaluation_setup" in self.config and "scripts" in self.config["evaluation_setup"]):
            raise RuntimeError("缺少evaluation_setup或script")
        
        for script in self.config["evaluation_setup"]["scripts"]:
            script_path = os.path.realpath(os.path.join(self.task_path,script["path"])) # panic if path is not exist
            if not os.path.exists(script_path):
                raise RuntimeError("脚本文件不存在")
            
            match script["role"]:
                case "hook":
                    if "dependency" in script:
                        dep_script_list = []
                        for dep in script["dependency"]:
                            dep_path = os.path.realpath(os.path.join(self.task_path,dep))
                            if not os.path.exists(dep_path):
                                raise RuntimeError("hook dependency文件不存在")
                            with open(dep_path, 'r') as f:
                                dep_script_list.append(f.read())
                        dep_script = "\n".join(dep_script_list)
                    else:
                        dep_script = ""
                    self.hook_manager.add_script(script_path, dep_script)
                case "handler":    
                    self.set_message_handler(script_path)
        self.logger.info(f"评估器初始化完成: {self.task_id}")

    @property
    def default_instruction(self) -> str:
        """返回加载并渲染后的任务指令"""
        return getattr(self, 'instruction', '') # Use getattr for safety

    def record_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        """
        记录一个标准化的 AgentEvent。
        
        Args:
            event_type: 事件类型 (AgentEvent 枚举成员)。
            data: 事件相关数据。
        """
        # 确保时间戳存在 (ResultCollector 也会检查)
        if 'timestamp' not in data:
            data['timestamp'] = time.time()

        self.result_collector.record_event(self.task_id, event_type, data)
        # 减少日志冗余，debug 级别由 ResultCollector 控制
        # self.logger.debug(f"记录事件: {event_type.name} - {data}")

    def set_message_handler(self,module_path) -> None:
        # 尝试导入对应的handler模块
        try:
            if os.path.exists(module_path):
                spec = importlib.util.spec_from_file_location("handler", module_path)
                handler_module = importlib.util.module_from_spec(spec)
                sys.modules["handler"] = handler_module
                spec.loader.exec_module(handler_module)
            
                if hasattr(handler_module, 'message_handler'):
                    self.message_handler = handler_module.message_handler
                    self.logger.info(f"成功设置回调函数: {module_path}.message_handler")
                else:
                    self.logger.warning(f"未找到回调函数: {module_path}")
            else:
                self.logger.warning(f"回调函数文件不存在: {module_path}")
        except Exception as e:
            self.logger.error(f"导入回调函数模块失败: {str(e)}")

    def _on_message(self, message: Dict[str, Any], data: Any) -> None:
        """
        内部消息处理函数，由 HookManager 调用。
        调用任务特定的 message_handler 并根据其返回的状态更新列表触发事件记录和回调。

        Args:
            message: 消息对象 (通常来自脚本)
            data: 附加数据
        """
        if not self.message_handler:
            return

        try:
            # 调用 handler，期望返回 Optional[List[Dict[str, Any]]]
            handler_updates = self.message_handler(message, self.logger, self.config.get('task_parameters', {}))
        except Exception as e:
            self.logger.error(f"执行 message_handler 时出错: {e}", exc_info=True)
            # 记录错误并触发回调
            error_reason = f"Handler execution error: {e}"
            current_time = time.time()
            self.record_event(AgentEvent.AGENT_ERROR_OCCURRED, {
                'timestamp': current_time,
                'error': 'Handler Exception',
                'message': str(e)
            })
            self.record_event(AgentEvent.TASK_END, {
                'timestamp': current_time,
                'status': 'failure',
                'reason': error_reason
            })
            # 直接触发回调并设置最终状态标志
            self._trigger_completion_callbacks(CallbackEventData("task_error", error_reason))
            self._final_callback_triggered = True # Ensure flag is set even on handler exception
            return

        if handler_updates is None or not isinstance(handler_updates, list):
            # Handler 返回 None 或无效类型，表示没有重要状态更新
            return

        current_time = time.time() # Use a consistent timestamp for events derived from this handler call

        for update in handler_updates:
            if not isinstance(update, dict):
                self.logger.warning(f"Handler 返回列表中包含无效项: {update}")
                continue

            status = update.get('status')

            # 根据 handler 返回的 status 处理
            match status:
                case 'success':
                    reason = update.get('reason', 'Handler reported success')
                    self.logger.info(f"Handler reported success: {reason}")
                    # 记录 TASK_END 事件
                    self.record_event(AgentEvent.TASK_END, {
                        'timestamp': current_time,
                        'status': 'success',
                        'reason': reason
                    })
                    # 触发成功回调
                    self._trigger_completion_callbacks(CallbackEventData("task_completed", reason))

                case 'error':
                    error_type = update.get('type', 'handler_error')
                    error_message = update.get('message', 'Handler reported error')
                    stack_trace = update.get('stack_trace')
                    error_reason = f"{error_type}: {error_message}"
                    self.logger.error(f"Handler reported error: {error_reason}")
                    # 记录 AGENT_ERROR_OCCURRED
                    error_data = {
                        'timestamp': current_time,
                        'error': error_type,
                        'message': error_message,
                    }
                    if stack_trace:
                        error_data['stack_trace'] = stack_trace
                    self.record_event(AgentEvent.AGENT_ERROR_OCCURRED, error_data)
                    # 记录 TASK_END 事件
                    self.record_event(AgentEvent.TASK_END, {
                        'timestamp': current_time,
                        'status': 'failure',
                        'reason': error_reason
                    })
                    # 触发错误回调
                    self._trigger_completion_callbacks(CallbackEventData("task_error", error_reason))

                case 'key_step':
                    step_index = update.get('index')
                    name_from_handler = update.get('name') # Handler 可以覆盖默认名称

                    if not isinstance(step_index, int) or step_index <= 0:
                        self.logger.warning(f"Handler 返回 key_step 状态包含无效索引: {update}")
                        continue

                    if step_index > self.total_key_steps:
                         self.logger.warning(f"Handler 返回 key_step 索引 {step_index} 超出配置的总步数 {self.total_key_steps}")
                         # 选择继续记录或跳过，这里选择记录但警告

                    # 去重检查由 KeyStepMetric 负责，BaseEvaluator 只负责记录
                    # 获取 Handler 提供的名称 (可能为 None)
                    name_from_handler = update.get('name')
                    self.logger.info(f"Handler reported key step completion: Index={step_index}, Name from Handler='{name_from_handler}'")

                    # 记录 KEY_STEP_COMPLETED 事件, 只包含 Handler 提供的 name (如果存在)
                    event_data = {
                        'timestamp': current_time,
                        'step_index': step_index,
                    }
                    if name_from_handler is not None:
                        event_data['step_name'] = name_from_handler # KeyStepMetric 会处理这个
                    self.record_event(AgentEvent.KEY_STEP_COMPLETED, event_data)

                case 'app_event': # 用于记录非关键、但可能需要追踪的应用内部事件
                    event_name = update.get('name', 'unknown_app_event')
                    event_payload = update.get('payload', {})
                    self.logger.debug(f"Handler reported app event: {event_name}, Data: {event_payload}")
                    # 记录 APP_SPECIFIC_EVENT
                    self.record_event(AgentEvent.APP_SPECIFIC_EVENT, {
                        'timestamp': current_time,
                        'name': event_name,
                        'payload': event_payload
                    })

                case 'continue' | None: # Handler 明确表示继续或无更新
                    pass

                case _:
                    self.logger.warning(f"Handler 返回列表中包含无法识别的状态: '{status}' in {update}")

    def register_completion_callback(self, callback: Callable[[CallbackEventData, 'BaseEvaluator'], None]) -> None:
        """
        注册任务完成时的回调函数，会回溯影响主程序 run_evaluator 的逻辑
        
        Args:
            callback: 回调函数，接收 CallbackEventData 和评估器实例作为参数
        """
        self.completion_callbacks.append(callback)
        self.logger.info("注册了新的完成回调函数")

    def _trigger_completion_callbacks(self, event_data: CallbackEventData) -> None:
        """
        触发所有注册的完成回调函数
        
        Args:
            event_data: 包含事件类型和消息的回调事件数据。
        """
        self.logger.info(f"触发回调: {event_data.event_type} - {event_data.message}")
        # Set flag if this is a final state callback
        if event_data.event_type in ["task_completed", "task_error"]:
            self._final_callback_triggered = True

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

        if not self.hook_manager.app_started:
            # 恢复用户数据
            try:
                data_restore_config = self.config.get("context_data", [])
                for config in data_restore_config:
                    from_relative_path = config.get("from")
                    from_path = os.path.join(self.canary_root, from_relative_path)
                    to_path = config.get("to")
                    restore_context_data(from_path, to_path)
            except Exception as e:
                self.logger.error(f"无法从{str(e)}恢复用户数据")
                return False
            self.logger.info("用户数据成功恢复")
            self.start_app()

        try:
            self.is_running = True

            # 1. 准备 session_data (包含配置快照)
            session_data = {
                # "config": self.config, # 移除，task_config 单独传递
                "app_path": self.hook_manager.app_path,
                "app_process_pid": self.hook_manager.app_process.pid if self.hook_manager.app_process else None
            }
            # 2. 启动 ResultCollector 会话并注册指标 (必须在 hook 加载前)
            self.result_collector.start_session(self.task_id, session_data, self.config)

            # Record TASK_START event immediately after session starts
            self.record_event(AgentEvent.TASK_START, {'timestamp': self.result_collector.results[self.task_id]['metadata']['session_start_unix']})

            # 3. 加载钩子脚本，这可能会立即开始发送事件
            self.hook_manager.load_scripts(self._on_message)

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

            # 结束会话并计算最终指标
            self.result_collector.end_session(self.task_id)

            # 如果最终的回调（成功/失败）尚未被触发，则记录 TASK_END 事件
            if not self._final_callback_triggered:
                stop_message = "Evaluator stopped externally or timed out before handler completion"
                self.logger.warning(stop_message)
                self.record_event(AgentEvent.TASK_END, {"status": "stopped", "reason": stop_message})
                # Optionally trigger an "evaluator_stopped" callback if needed for external logic
                # self._trigger_completion_callbacks(CallbackEventData("evaluator_stopped", stop_message))

            # 保存结果（现在包含计算好的指标）
            self.save_results() # <- MOVED here, ensures save happens once at the end
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

        # 从 ResultCollector 获取最终结果
        results = self.result_collector.get_results(self.task_id)
        metadata = results.get('metadata', {})
        computed_metrics = results.get('computed_metrics', {})
        raw_events = results.get('raw_events', [])

        # 使用 metadata 中的时间信息
        start_time_iso = metadata.get("session_start_iso", "未知")
        end_time_iso = metadata.get("session_end_iso", "未知")
        duration_val = metadata.get("session_duration_seconds")
        duration_str = f"{duration_val:.2f}" if isinstance(duration_val, (int, float)) else "未知"

        # 基本报告模板
        report_content = f"""# {self.task_id} 评估报告

## 基本信息
- 任务ID: {self.task_id}
- 会话ID: {self.session_id}
- 开始时间: {start_time_iso}
- 结束时间: {end_time_iso}
- 总耗时: {duration_str} 秒

## 评估指标
"""
        # 添加计算出的指标
        if computed_metrics:
            for name, value in computed_metrics.items():
                # 对复杂值进行 JSON 格式化以便阅读
                value_str = json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, (dict, list)) else value
                report_content += f"- {name}: {value_str}\n"
        else:
            report_content += "- 未计算出指标。\n"

        # 添加事件日志
        report_content += "\n## 事件日志\n"
        if raw_events:
            for event in raw_events:
                ts = event.get('timestamp', 0)
                event_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) if ts else "N/A"
                event_type_str = event.get('event_type', 'UNKNOWN_EVENT')
                event_data_str = json.dumps({k: v for k, v in event.items() if k not in ['timestamp', 'event_type']}, ensure_ascii=False)
                report_content += f"- [{event_time_str}] {event_type_str}: {event_data_str}\n"
        else:
            report_content += "- 无原始事件记录。\n"

        # 写入报告文件
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            self.logger.info(f"评估报告已生成: {report_path}")
        except Exception as e:
             self.logger.error(f"生成评估报告失败: {e}", exc_info=True)
             return "" # 返回空字符串表示失败

        return report_path
