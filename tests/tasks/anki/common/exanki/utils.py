from typing import Dict, Any, Optional


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

