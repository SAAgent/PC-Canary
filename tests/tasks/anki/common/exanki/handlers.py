from .context import Context
from typing import Dict, Any, Optional

HANDLERS = None

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    CONTEXT = message_handler.context 
    if CONTEXT is None:
        raise RuntimeError("Context is not initialized")
    event_type = message.get('type')
    if event_type == "send":
        message = message.get('payload')
        event_type = message.get('type')
    match event_type:
        case 'trace':
            function_name = message["function"]
            return CONTEXT.handle_trace(function_name,message, data)
        case "error":
            CONTEXT.log("error",str(message))
        case 'log':
            CONTEXT.log(message["level"],message["msg"])
    return None


def bind_handlers(handlers:Dict):
    global HANDLERS
    HANDLERS = handlers
    
def register_handlers(evaluator):
    config = evaluator.config
    if not "sql_path" in config:
        raise RuntimeError("Missing database file path")
    global HANDLERS
    if HANDLERS is None:
        raise RuntimeError("Handlers are not initialized")
    CONTEXT = Context(evaluator)
    CONTEXT.register_trace_handlers(HANDLERS)
    message_handler.context = CONTEXT
    return message_handler


