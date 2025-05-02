# evaluator/metrics/standard_metrics.py
import time
from typing import Dict, Any, Optional, List, Tuple
import logging

from collections import defaultdict
from evaluator.core.metrics.base_metrics import BaseMetric
from evaluator.core.events import AgentEvent

# TODO 这样子实现的话，每次维护成员变量都需要传入 Event 实例和 data，且 data 需要规范，可能需要提供一个更简单的接口
class TotalTimeMetric(BaseMetric):
    """计算任务总耗时的指标。"""
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.task_start_time: Optional[float] = None
        self.task_end_time: Optional[float] = None

    def get_name(self) -> str:
        return "total_duration_seconds"

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        super().process_event(event_type, data)
        timestamp = data.get('timestamp', time.time())

        if event_type == AgentEvent.TASK_START:
            if self.task_start_time is None:
                self.task_start_time = timestamp
                self.logger.debug(f"记录任务开始时间: {self.task_start_time}")
        elif event_type == AgentEvent.TASK_END:
             # 记录最后一次 TASK_END 作为结束时间
             self.task_end_time = timestamp
             self.logger.debug(f"记录任务结束时间: {self.task_end_time}")

    def get_value(self) -> Optional[float]:
        if self.task_start_time is not None and self.task_end_time is not None:
            duration = self.task_end_time - self.task_start_time
            return round(duration, 3)
        self.logger.warning(f"无法计算总时长，开始: {self.task_start_time}, 结束: {self.task_end_time}")
        return None

    def reset(self) -> None:
        super().reset()
        self.task_start_time = None
        self.task_end_time = None

class LLMCallCounterMetric(BaseMetric):
    """统计 LLM 调用次数的指标。"""
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.call_count = 0

    def get_name(self) -> str:
        return "llm_call_count"

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        super().process_event(event_type, data)
        if event_type == AgentEvent.LLM_QUERY_START: # 在请求开始时计数
            self.call_count += 1
            self.logger.debug(f"LLM 调用次数增加: {self.call_count}")

    def get_value(self) -> int:
        return self.call_count

    def reset(self) -> None:
        super().reset()
        self.call_count = 0

class TokenCounterMetric(BaseMetric):
    """统计 LLM Token 消耗的指标。"""
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0

    def get_name(self) -> str:
        return "llm_token_usage"

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        super().process_event(event_type, data)
        # TODO 这样的写法意味着 data 的格式可能是各不一样的或者需要设计某种规范的格式
        if event_type == AgentEvent.LLM_QUERY_END and data.get('status') == 'success':
            prompt_tokens = data.get('prompt_tokens', 0)
            completion_tokens = data.get('completion_tokens', 0)
            if isinstance(prompt_tokens, int) and isinstance(completion_tokens, int):
                self.total_prompt_tokens += prompt_tokens
                self.total_completion_tokens += completion_tokens
                self.total_tokens = self.total_prompt_tokens + self.total_completion_tokens
                self.logger.debug(f"Token 累计: Prompt={self.total_prompt_tokens}, Completion={self.total_completion_tokens}, Total={self.total_tokens}")
            else:
                self.logger.warning(f"LLM_QUERY_END 事件缺少有效的 token 数据: {data}")

    def get_value(self) -> Dict[str, int]:
        return {
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
        }

    def reset(self) -> None:
        super().reset()
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0

class TaskCompletionStatusMetric(BaseMetric):
    """
    记录任务最终完成状态的基础指标。
    主要依赖 TASK_END 事件。任务特定的成功/失败判断应由子类或
    其他监听 APP_SPECIFIC_EVENT 的指标处理，并最终影响 TASK_END 的状态。
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.status = "unknown"
        self.reason = ""

    def get_name(self) -> str:
        return "task_completion_status"

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        super().process_event(event_type, data)
        if event_type == AgentEvent.TASK_END:
            task_status = data.get('status', 'failure') # 默认为失败，除非明确成功或超时
            self.status = task_status
            self.reason = data.get('reason', '')
            self.logger.info(f"记录任务最终状态: {self.status}, 原因: {self.reason}")

    def get_value(self) -> Dict[str, str]:
        return {"status": self.status, "reason": self.reason}

    def reset(self) -> None:
        super().reset()
        self.status = "unknown"
        self.reason = ""

class AgentSelfReportedCompletionMetric(BaseMetric):
    """记录Agent是否认为自己完成了任务。"""
    # TODO 这可能需要修改原始 computer use 的 prompt，设计一个 agent 自己的报告
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.agent_reported_completion = False
        self.reasoning = None

    def get_name(self) -> str:
        return "agent_reported_completion"

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        super().process_event(event_type, data)
        if event_type == AgentEvent.AGENT_REPORTED_COMPLETION:
            self.agent_reported_completion = True
            self.reasoning = data.get('reasoning')
            self.logger.info(f"Agent报告任务完成。推理: {self.reasoning}")
        elif event_type == AgentEvent.STEP_END and data.get('agent_believes_completed'):
             self.agent_reported_completion = True
             self.reasoning = data.get('reasoning', 'Indicated in STEP_END')
             self.logger.info(f"Agent在步骤结束时表明任务完成。")


    def get_value(self) -> Dict[str, Any]:
        return {
            "completed": self.agent_reported_completion,
            "reasoning": self.reasoning
            }

    def reset(self) -> None:
        super().reset()
        self.agent_reported_completion = False
        self.reasoning = None

class ToolUsageMetric(BaseMetric):
    """跟踪工具使用情况的指标，包括调用次数、成功/失败、参数和错误。"""
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        # 存储结构: {tool_name: {'calls': [], 'total_count': 0, 'success_count': 0, 'failure_count': 0}}
        self.tool_stats = defaultdict(lambda: {
            'calls': [],
            'total_count': 0,
            'success_count': 0,
            'failure_count': 0
        })
        self.total_tool_calls = 0

    def get_name(self) -> str:
        return "tool_usage_stats"

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        super().process_event(event_type, data)
        timestamp = data.get('timestamp')

        if event_type == AgentEvent.TOOL_CALL_START:
            tool_name = data.get('tool_name')
            args = data.get('args')
            if tool_name:
                self.tool_stats[tool_name]['calls'].append({
                    'start_time': timestamp,
                    'args': args,
                    'end_time': None,
                    'success': None,
                    'result': None,
                    'error': None
                })
                self.tool_stats[tool_name]['total_count'] += 1
                self.total_tool_calls += 1
                self.logger.debug(f"工具调用开始: {tool_name}, Args: {args}")
            else:
                self.logger.warning(f"TOOL_CALL_START 事件缺少 tool_name: {data}")

        elif event_type == AgentEvent.TOOL_CALL_END:
            tool_name = data.get('tool_name')
            success = data.get('success')
            result = data.get('result')
            error = data.get('error')

            if tool_name and tool_name in self.tool_stats:
                 # 找到对应的 'start' 调用并更新它
                 # 假设调用是顺序的，更新最后一个未完成的调用
                 call_list = self.tool_stats[tool_name]['calls']
                 if call_list and call_list[-1]['end_time'] is None:
                     last_call = call_list[-1]
                     last_call.update({
                         'end_time': timestamp,
                         'success': success,
                         'result': result,
                         'error': error
                     })

                     if success:
                         self.tool_stats[tool_name]['success_count'] += 1
                         self.logger.debug(f"工具调用成功: {tool_name}")
                     else:
                         self.tool_stats[tool_name]['failure_count'] += 1
                         self.logger.warning(f"工具调用失败: {tool_name}, Error: {error}")
                 else:
                    self.logger.error(f"收到 TOOL_CALL_END 但找不到匹配的开始事件或调用已结束: {tool_name}")

            elif tool_name:
                 self.logger.error(f"收到 TOOL_CALL_END 但未记录该工具的开始事件: {tool_name}")
            else:
                self.logger.warning(f"TOOL_CALL_END 事件缺少 tool_name: {data}")


    def get_value(self) -> Dict[str, Any]:
        # 返回处理后的统计信息，可以不包含原始 calls 列表以简化输出
        summary = {
            "total_tool_calls": self.total_tool_calls,
            "tools": {}
        }
        for name, stats in self.tool_stats.items():
            summary["tools"][name] = {
                "total_count": stats['total_count'],
                "success_count": stats['success_count'],
                "failure_count": stats['failure_count'],
                # 可以选择性地添加最后一次调用的信息
                "last_call": stats['calls'][-1] if stats['calls'] else None
            }
        return summary

    def reset(self) -> None:
        super().reset()
        self.tool_stats = defaultdict(lambda: {
            'calls': [], 'total_count': 0, 'success_count': 0, 'failure_count': 0
        })
        self.total_tool_calls = 0
