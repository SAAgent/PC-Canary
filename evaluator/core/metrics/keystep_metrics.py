# evaluator/metrics/task_metrics.py (or a new file like ordered_step_metric.py)
import logging
from typing import Dict, Any, Optional, List, Set
from evaluator.core.metrics.base_metrics import BaseMetric # Adjust import if needed
from evaluator.core.events import AgentEvent

class KeyStepMetric(BaseMetric):
    """
    Tracks completion of ordered key steps based on KEY_STEP_COMPLETED events.
    Assumes steps are indexed sequentially starting from 1.
    """
    def __init__(self, total_steps: int, step_names: Optional[Dict[int, str]] = None, logger: Optional[logging.Logger] = None):
        """
        Args:
            total_steps: The total number of key steps defined for the task.
            step_names: Optional mapping from step_index to a readable name.
            logger: Logger instance.
        """
        super().__init__(logger)
        if total_steps <= 0:
            raise ValueError("Total steps must be positive.")
        self.total_steps = total_steps
        self.step_names = step_names or {}
        self.completed_indices: Set[int] = set()
        self.completion_details: List[Dict] = []

    def get_name(self) -> str:
        return "key_step_tracker"

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        super().process_event(event_type, data)
        timestamp = data.get('timestamp')
        # TODO 感觉有 bug，需要测试
        if event_type == AgentEvent.KEY_STEP_COMPLETED:
            step_index = data.get('step_index')
            step_name_provided = data.get('step_name') # Name sent by handler

            if isinstance(step_index, int) and 1 <= step_index <= self.total_steps:
                if step_index not in self.completed_indices:
                    self.completed_indices.add(step_index)
                    # Use name from handler if provided, else from config, else just index
                    name = step_name_provided or self.step_names.get(step_index, f"Step {step_index}")
                    self.completion_details.append({
                        "step_index": step_index,
                        "step_name": name,
                        "timestamp": timestamp,
                    })
                    self.logger.info(f"关键步骤完成: Index={step_index}, Name='{name}'")
                # else: # Decide if logging duplicates is useful
                #     self.logger.debug(f"收到重复的关键步骤完成事件: Index={step_index}")
            else:
                self.logger.warning(f"收到的 KEY_STEP_COMPLETED 事件包含无效或越界的索引: {step_index}")

    def get_value(self) -> Dict[str, Any]:
        completed_count = len(self.completed_indices)
        highest_index = max(self.completed_indices) if self.completed_indices else 0
        completion_rate_by_count = (completed_count / self.total_steps) if self.total_steps > 0 else 0
        completion_rate_by_progress = (highest_index / self.total_steps) if self.total_steps > 0 else 0
        final_step_reached = self.total_steps in self.completed_indices

        return {
            "total_steps": self.total_steps,
            "completed_steps_count": completed_count,
            "highest_index_reached": highest_index,
            "completion_rate_by_count": round(completion_rate_by_count, 2),
            "completion_rate_by_progress": round(completion_rate_by_progress, 2), # Based on furthest step
            "final_step_reached": final_step_reached,
            "completed_indices_list": sorted(list(self.completed_indices)),
            "completion_timeline": sorted(self.completion_details, key=lambda x: x.get('timestamp', 0))
        }

    def reset(self) -> None:
        super().reset()
        self.completed_indices = set()
        self.completion_details = []