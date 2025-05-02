# evaluator/core/events.py
from enum import Enum, auto

class AgentEvent(Enum):
    # Task Lifecycle
    TASK_START = auto()                    # data: {'timestamp'}
    TASK_END = auto()                      # data: {'timestamp', 'status': 'success'|'failure'|'timeout'|'stopped', 'reason': str}

    # Agent Internal State / Perception (Optional but useful)
    STEP_START = auto()                    # data: {'timestamp', 'step_name': str (optional)}
    STEP_END = auto()                      # data: {'timestamp', 'step_name': str (optional), 'status': 'success'|'failure', 'agent_believes_completed': bool (optional)}
    AGENT_REPORTED_COMPLETION = auto()     # data: {'timestamp', 'reasoning': str (optional)}
    AGENT_ERROR_OCCURRED = auto()          # data: {'timestamp', 'error': str, 'stack_trace': str (optional)}

    # LLM Interaction
    LLM_QUERY_START = auto()               # data: {'timestamp', 'model_name': str (optional)}
    LLM_QUERY_END = auto()                 # data: {'timestamp', 'prompt_tokens': int (optional), 'completion_tokens': int (optional), 'cost': float (optional), 'status': 'success'|'error', 'error': str (optional)}

    # Tool Interaction
    TOOL_CALL_START = auto()               # data: {'timestamp', 'tool_name': str, 'args': dict}
    TOOL_CALL_END = auto()                 # data: {'timestamp', 'tool_name': str, 'success': bool, 'result': Any (optional), 'error': str (optional)}

    # Application Interaction (via HookManager/Handler)
    APP_SPECIFIC_EVENT = auto()            # data: {'timestamp', ...original_payload from app/frida}
    KEY_STEP_COMPLETED = auto()