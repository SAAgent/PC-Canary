# evaluator/core/result_collector.py
import os
import time
import json
import logging
from typing import Dict, Any, Optional, List, Type
from collections import defaultdict

# 核心依赖
from evaluator.core.events import AgentEvent
from evaluator.core.metrics.base_metrics import BaseMetric

# 导入需要注册的标准和特定指标类 (根据你的文件结构调整路径)
from evaluator.core.metrics.standard_metrics import (
    TotalTimeMetric,
    LLMCallCounterMetric,
    TokenCounterMetric,
    TaskCompletionStatusMetric,
    AgentSelfReportedCompletionMetric,
    ToolUsageMetric
)

from evaluator.core.metrics.error_metrics import ErrorCounterMetric
from evaluator.core.metrics.keystep_metrics import KeyStepMetric


class ResultCollector:
    """
    结果收集器 V2:
    负责收集原始事件流，管理指标计算器实例，分发事件，
    并在评估结束时聚合和保存最终结果。
    """

    def __init__(self,
                 output_dir: str = "results",
                 logger: Optional[logging.Logger] = None):
        """
        初始化结果收集器。

        Args:
            output_dir: 结果输出目录。
            logger: 日志记录器。
        """
        self.output_dir = output_dir
        # 主数据结构: task_id -> {metadata, raw_events, computed_metrics}
        self.results: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "metadata": {},
            "raw_events": [],
            "computed_metrics": {}
        })
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)

        # 持有每个任务注册的指标实例: task_id -> List[BaseMetric]
        self.registered_metrics: Dict[str, List[BaseMetric]] = defaultdict(list)

        os.makedirs(output_dir, exist_ok=True)
        self.logger.info(f"结果收集器初始化完成，结果将保存在: {output_dir}")

    def _register_metrics_for_task(self, task_id: str, task_config: Dict[str, Any]):
        """
        为指定任务注册默认和任务特定的指标实例。
        只有在该任务初始配置时调用 (例如在 start_session 中)。

        Args:
            task_id: 要注册指标的任务 ID。
            task_config: 该任务的配置字典，用于初始化特定指标。
        """
        if task_id in self.registered_metrics and self.registered_metrics[task_id]:
            self.logger.warning(f"任务 {task_id} 的指标已经注册，跳过。")
            return

        metrics_to_register: List[BaseMetric] = []
        self.logger.info(f"开始为任务 {task_id} 注册指标...")

        # --- 1. 注册通用指标 ---
        standard_metric_classes: List[Type[BaseMetric]] = [
            TotalTimeMetric,
            LLMCallCounterMetric,
            TokenCounterMetric,
            TaskCompletionStatusMetric,
            AgentSelfReportedCompletionMetric,
            ToolUsageMetric,
            ErrorCounterMetric,
        ]
        for metric_cls in standard_metric_classes:
            try:
                # 将 logger 传递给指标实例
                instance = metric_cls(logger=self.logger.getChild(metric_cls.__name__))
                metrics_to_register.append(instance)
                self.logger.debug(f"注册标准指标: {instance.get_name()} for task {task_id}")
            except Exception as e:
                self.logger.error(f"注册标准指标 {metric_cls.__name__} (任务 {task_id}) 失败: {e}", exc_info=True)

        # --- 2. 注册任务特定指标 (示例: KeyStepMetric) ---
        # 查找任务配置中关于关键步骤的信息
        key_steps_info = task_config.get('key_steps')
        if key_steps_info and isinstance(key_steps_info, dict):
            total_steps = key_steps_info.get('total_steps')
            step_names_config = key_steps_info.get('step_names') # Optional map {index_str: name}

            if isinstance(total_steps, int) and total_steps > 0:
                # 解析步骤名称映射 (将 key 从 str 转为 int) TODO 这是在干什么
                parsed_step_names = {}
                if isinstance(step_names_config, dict):
                    for k, v in step_names_config.items():
                        try:
                            parsed_step_names[int(k)] = v
                        except (ValueError, TypeError):
                            self.logger.warning(f"无法将步骤名称键 '{k}' 转换为整数 (任务 {task_id})，已忽略。")

                try:
                    instance = KeyStepMetric(
                        total_steps=total_steps,
                        step_names=parsed_step_names,
                        logger=self.logger.getChild(KeyStepMetric.__name__)
                    )
                    metrics_to_register.append(instance)
                    self.logger.debug(f"注册任务特定指标: {instance.get_name()} for task {task_id}")
                except ValueError as ve:
                        self.logger.error(f"注册 KeyStepMetric (任务 {task_id}) 失败: {ve}")
                except Exception as e:
                     self.logger.error(f"注册 KeyStepMetric (任务 {task_id}) 时发生未知错误: {e}", exc_info=True)
            else:
                self.logger.warning(f"配置中找到 key_steps_info，但 total_steps 无效 (任务 {task_id})，无法注册 KeyStepMetric。")
        else:
             self.logger.info(f"任务 {task_id} 配置中未找到有效的 key_steps，跳过注册 KeyStepMetric。")

        # --- (可以添加更多基于配置加载新的特定指标的逻辑) ---
        # 例如: if task_config.get('requires_custom_metric_X'): register CustomMetricX(...)

        self.registered_metrics[task_id] = metrics_to_register
        self.logger.info(f"任务 {task_id} 的指标注册完成，共 {len(metrics_to_register)} 个指标。")


    def start_session(self, task_id: str, session_data: Dict[str, Any], task_config: Dict[str, Any]) -> None:
        """
        开始一个评估会话，注册指标并记录元数据。

        Args:
            task_id: 任务ID。
            session_data: 会话初始元数据 (如 app_path, pid)。
            task_config: 该任务的完整配置字典。
        """
        # 确保为这个任务注册指标 (如果尚未注册)
        self._register_metrics_for_task(task_id, task_config)

        # 初始化或重置结果结构（如果之前运行过）
        self.results[task_id] = {
            "metadata": {},
            "raw_events": [],
            "computed_metrics": {}
        }
        # 重置该任务的指标状态
        self.reset_metrics(task_id)

        now = time.time()
        self.results[task_id]['metadata'] = {
            "session_start_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
            "session_start_unix": now,
            "task_config_at_start": task_config, # 存储任务配置快照
            **session_data # 合并传入的元数据
        }

        self.logger.info(f"任务会话开始: {task_id}")


    def record_event(self, task_id: str, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        """
        记录一个标准化的 AgentEvent，并将其分发给该任务已注册的指标处理器。

        Args:
            task_id: 任务ID。
            event_type: 事件类型 (AgentEvent 枚举成员)。
            data: 事件相关数据 (应包含 'timestamp')。
        """
        # 确保时间戳存在 (BaseEvaluator也应该做这个检查)
        if 'timestamp' not in data:
            data['timestamp'] = time.time()

        # --- 1. 存储原始事件 ---
        # 添加事件类型名称以便于阅读原始日志
        raw_event_entry = {
            'event_type': event_type.name,
            **data
        }
        # 使用 defaultdict 后无需检查 key 是否存在
        self.results[task_id]['raw_events'].append(raw_event_entry)
        # 减少日志冗余，只在 DEBUG 级别记录详细数据
        self.logger.debug(f"记录原始事件: {task_id} - {event_type.name} - {data if self.logger.isEnabledFor(logging.DEBUG) else '...'}")

        # --- 2. 分发给指标处理器 ---
        if task_id in self.registered_metrics:
            for metric in self.registered_metrics[task_id]:
                try:
                    # 每个指标自己处理是否关心此事件
                    metric.process_event(event_type, data)
                except Exception as e:
                    # 记录错误，但继续处理其他指标
                    self.logger.error(f"指标 {metric.get_name()} 处理事件 {event_type.name} (任务 {task_id}) 时出错: {e}", exc_info=True)
        else:
            # 这通常不应该发生，因为 start_session 会注册指标
            self.logger.warning(f"任务 {task_id} 没有注册的指标，无法分发事件 {event_type.name}。")


    def finalize_results(self, task_id: str) -> None:
        """
        在评估结束时，计算所有注册指标的最终值。
        此方法应在 end_session 内部或之前显式调用。
        """
        if task_id not in self.results:
            self.logger.error(f"无法最终化结果，任务 {task_id} 的结果结构不存在。")
            return

        self.logger.info(f"开始为任务 {task_id} 计算最终指标...")
        computed_metrics: Dict[str, Any] = {}

        if task_id in self.registered_metrics:
            for metric in self.registered_metrics[task_id]:
                metric_name = metric.get_name()
                try:
                    metric_value = metric.get_value()
                    computed_metrics[metric_name] = metric_value
                    # 减少日志冗余，只在 DEBUG 级别记录每个值
                    self.logger.debug(f"指标计算完成 ({task_id}): {metric_name} = {metric_value if self.logger.isEnabledFor(logging.DEBUG) else '...'}")
                except Exception as e:
                    self.logger.error(f"获取指标 {metric_name} 的值 (任务 {task_id}) 时出错: {e}", exc_info=True)
                    computed_metrics[metric_name] = f"ERROR_GETTING_VALUE: {e}" # 在结果中记录错误
        else:
             self.logger.warning(f"任务 {task_id} 没有注册的指标，无法计算最终值。")

        # 将计算出的指标存储在结果结构中
        self.results[task_id]['computed_metrics'] = computed_metrics
        self.logger.info(f"任务 {task_id} 的最终指标计算完成。")


    def end_session(self, task_id: str, session_data: Dict[str, Any] = None) -> None:
        """
        结束一个评估会话，计算最终指标并记录结束时间。

        Args:
            task_id: 任务ID。
            session_data: 会话结束时要补充的元数据 (可选)。
        """
        if task_id not in self.results:
            self.logger.error(f"无法结束会话，任务 {task_id} 不存在或未开始。")
            return

        # --- 1. 确保最终指标被计算 ---
        self.finalize_results(task_id)

        # --- 2. 记录结束时间和总时长 ---
        now = time.time()
        metadata = self.results[task_id]['metadata']
        metadata["session_end_iso"] = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now))
        metadata["session_end_unix"] = now

        start_time = metadata.get("session_start_unix")
        duration = None
        if start_time:
            duration = round(now - start_time, 3)
            metadata["session_duration_seconds"] = duration

        # 合并任何额外的结束会话数据
        if session_data:
             metadata.update(session_data)

        self.logger.info(f"任务会话结束: {task_id}. 总时长: {duration if duration is not None else 'N/A'} 秒")


    def get_results(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        """
        获取指定任务或所有任务的评估结果。

        Args:
            task_id: 任务ID，为None则返回所有任务结果。

        Returns:
            评估结果字典。
        """
        if task_id is not None:
            # 返回深拷贝以防止外部修改内部状态？对于大型结果可能影响性能
            # import copy; return copy.deepcopy(self.results.get(task_id, {}))
            return self.results.get(task_id, {})
        # import copy; return copy.deepcopy(dict(self.results)) # 返回所有结果的拷贝
        return dict(self.results) # 返回浅拷贝

    def save_results(self, task_id: Optional[str] = None, filename_prefix: str = "result") -> str:
        """
        保存评估结果到 JSON 文件。

        Args:
            task_id: 任务ID，为None则保存所有任务结果到单个文件。
            filename_prefix: 生成的文件名前缀。

        Returns:
            结果文件路径，如果失败则返回空字符串。
        """
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        file_path = ""

        try:
            if task_id is not None:
                if task_id not in self.results:
                    self.logger.warning(f"无法保存结果，任务 {task_id} 的结果不存在。")
                    return ""
                file_path = os.path.join(self.output_dir, f"{filename_prefix}_{task_id}_{timestamp_str}.json")
                data_to_save = self.results[task_id]
                log_msg = f"任务 {task_id} 结果已保存: {file_path}"
            else:
                file_path = os.path.join(self.output_dir, f"{filename_prefix}_all_{timestamp_str}.json")
                data_to_save = dict(self.results) # 保存所有结果的快照
                log_msg = f"所有任务结果已保存: {file_path}"

            with open(file_path, 'w', encoding='utf-8') as f:
                # 使用 default=str 来处理无法序列化的类型 (例如 Enum 成员，如果它们最终进入数据)
                json.dump(data_to_save, f, indent=2, ensure_ascii=False, default=str)

            self.logger.info(log_msg)
            return file_path
        except TypeError as te:
             self.logger.error(f"保存结果到 {file_path} 时发生序列化错误: {te}. 确保指标的 get_value() 返回 JSON 兼容类型。", exc_info=True)
             return ""
        except Exception as e:
            self.logger.error(f"保存结果到 {file_path} 失败: {e}", exc_info=True)
            return ""


    def clear_results(self, task_id: Optional[str] = None) -> None:
        """
        清除内存中的指定任务或所有任务的评估结果和指标实例。

        Args:
            task_id: 任务ID，为None则清除所有结果。
        """
        tasks_to_clear = [task_id] if task_id and task_id in self.results else list(self.results.keys()) if task_id is None else []

        if not tasks_to_clear and task_id:
             self.logger.warning(f"尝试清除不存在的任务结果: {task_id}")
             return
        elif not tasks_to_clear and task_id is None:
            self.logger.info("没有结果需要清除。")
            return

        for tid in tasks_to_clear:
            if tid in self.results:
                del self.results[tid]
            if tid in self.registered_metrics:
                del self.registered_metrics[tid]
            self.logger.info(f"已清除任务 {tid} 的结果和指标实例。")

        if task_id is None:
             self.logger.info("已清除所有评估结果和指标实例。")


    def reset_metrics(self, task_id: Optional[str] = None) -> None:
        """
        重置指定任务或所有任务的所有已注册指标的内部状态。
        用于在不重新创建收集器的情况下运行新一轮评估。

        Args:
            task_id: 任务ID，为None则重置所有任务的指标。
        """
        tasks_to_reset = [task_id] if task_id and task_id in self.registered_metrics else list(self.registered_metrics.keys()) if task_id is None else []

        if not tasks_to_reset and task_id:
             self.logger.warning(f"尝试重置不存在的任务指标: {task_id}")
             return
        elif not tasks_to_reset and task_id is None:
            self.logger.info("没有指标需要重置。")
            return

        for tid in tasks_to_reset:
            self.logger.info(f"正在重置任务 {tid} 的指标状态...")
            metric_count = 0
            for metric in self.registered_metrics[tid]:
                try:
                    metric.reset()
                    metric_count += 1
                except Exception as e:
                    self.logger.error(f"重置指标 {metric.get_name()} (任务 {tid}) 时出错: {e}", exc_info=True)
            self.logger.info(f"任务 {tid} 的 {metric_count} 个指标已重置。")
            # 重置后也清除上次运行的计算结果和原始事件
            if tid in self.results:
                self.results[tid]['raw_events'] = []
                self.results[tid]['computed_metrics'] = {}