from .context import Context
from typing import Dict, Any, Optional, List

HANDLERS = None
DEPENDENCY_GRAPH = None
FINISHED_LIST = None
INIT = None

def message_handler(message: Dict[str, Any], logger, _task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
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
            return CONTEXT.handle_trace(function_name,message)
        case "error":
            return {
                "status" : "error",
                "type" : "script_error",
                "message" : message
            }
        case 'log':
            CONTEXT.log(message["level"],message["msg"])
    return None


def bind_handlers(handlers:Dict,dependency_graph,finished_condition,init=None):
    global HANDLERS,DEPENDENCY_GRAPH,FINISHED_LIST,INIT
    HANDLERS = handlers
    FINISHED_LIST = finished_condition
    DEPENDENCY_GRAPH = dependency_graph
    INIT = init
    
def register_handlers(evaluator):
    config = evaluator.config
    if not "sql_path" in config:
        raise RuntimeError("Missing database file path")
    global HANDLERS,DEPENDENCY_GRAPH,FINISHED_LIST
    if HANDLERS is None:
        raise RuntimeError("Handlers are not initialized")
    if DEPENDENCY_GRAPH is None:
        raise RuntimeError("Dependency graph is not initialized")
    if FINISHED_LIST is None:
        raise RuntimeError("Finished list is not initialized")
    CONTEXT = Context(evaluator,DEPENDENCY_GRAPH,FINISHED_LIST)
    CONTEXT.register_trace_handlers(HANDLERS)
    if INIT is not None:
        INIT(CONTEXT)
    message_handler.context = CONTEXT
    return message_handler


