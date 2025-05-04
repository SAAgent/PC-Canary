# evaluator/metrics/error_metrics.py
from typing import Dict, Any, Optional, List
import logging
from collections import defaultdict

from evaluator.core.metrics.base_metrics import BaseMetric
from evaluator.core.events import AgentEvent

class ErrorCounterMetric(BaseMetric):
    """分类统计不同来源错误的指标。"""
    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        # 存储结构: {error_source: {'count': N, 'errors': [...]}}
        self.error_stats = defaultdict(lambda: {'count': 0, 'errors': []})
        self.total_error_count = 0

    def get_name(self) -> str:
        return "error_summary"

    def _record_error(self, source: str, error_details: Any, timestamp: Optional[float]):
        self.error_stats[source]['count'] += 1
        self.error_stats[source]['errors'].append({
            'timestamp': timestamp,
            'details': error_details
        })
        self.total_error_count += 1
        self.logger.warning(f"记录到错误 - 来源: {source}, 详情: {error_details}")

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        super().process_event(event_type, data)
        # TODO data的规范很成问题，需要文档，这之后的处理可能也不容易
        timestamp = data.get('timestamp')

        if event_type == AgentEvent.LLM_QUERY_END and data.get('status') == 'error':
            self._record_error('LLM', data.get('error', 'Unknown LLM error'), timestamp)

        elif event_type == AgentEvent.TOOL_CALL_END and not data.get('success'):
            error_detail = {
                "tool_name": data.get('tool_name'),
                "error_message": data.get('error')
            }
            self._record_error('Tool', error_detail, timestamp)

        elif event_type == AgentEvent.AGENT_ERROR_OCCURRED:
            self._record_error('Agent', data.get('error', 'Unknown agent error'), timestamp)

        elif event_type == AgentEvent.APP_SPECIFIC_EVENT:
            # 检查是否是已知的应用/注入错误事件
            app_event_type = data.get("event")
            if app_event_type == "injection_error":
                self._record_error('injection', data.get('description', 'unknown error'), timestamp)
            elif app_event_type == "error": # 假设应用内部错误也用 "error"
                 error_detail = {
                    "type": data.get("error_type", "unknown"),
                    "message": data.get("message", "Unknown app error")
                 }
                 self._record_error('App', error_detail, timestamp)

        elif event_type == AgentEvent.TASK_END and data.get('status') == 'failure':
             # 记录由评估器检测到的任务失败（可能是超时或其他）
             if data.get('reason') and 'error' not in data.get('reason', '').lower(): # 避免重复记录已知错误
                 self._record_error('Evaluator', {'reason': data.get('reason')}, timestamp)


    def get_value(self) -> Dict[str, Any]:
        return {
            "total_error_count": self.total_error_count,
            "errors_by_source": dict(self.error_stats) # 转为普通字典输出
        }

    def reset(self) -> None:
        super().reset()
        self.error_stats = defaultdict(lambda: {'count': 0, 'errors': []})
        self.total_error_count = 0
