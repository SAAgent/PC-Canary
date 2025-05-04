# evaluator/metrics/base.py
import abc
import logging
import time
from typing import Dict, Any, Optional
from evaluator.core.events import AgentEvent

class BaseMetric(abc.ABC):
    """
    指标记录器的抽象基类。
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)
        self._start_time = None

    @abc.abstractmethod
    def get_name(self) -> str:
        pass

    def process_event(self, event_type: AgentEvent, data: Dict[str, Any]) -> None:
        # 基类可以记录第一次事件的时间戳
        if self._start_time is None and 'timestamp' in data:
             self._start_time = data['timestamp']

    @abc.abstractmethod
    def get_value(self) -> Any:
        pass

    def reset(self) -> None:
        self._start_time = None
        # 子类应在此处调用 super().reset() 并重置自己的状态
