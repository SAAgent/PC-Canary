from typing import Dict, Any, Callable
import zulip

client = zulip.Client(config_file="~/zuliprc")

def inspector_on_completion(handler: Callable[[Dict[str, Any], Any], None]):
    """
    在任务结束时调用, handler是用来处理获取得到的数据, 最终会调用到handler.py中的message_handler函数
    """
    # 获取消息, 然后使用handler处理消息
    result = client.get_profile()
    self_email = result.get('email', None)

    request_source_channel: dict[str, Any] = {
        "anchor": "newest",
        "num_before": 1,
        "num_after": 0,
        "narrow": [
            {"operator": "sender", "operand": self_email},
            {"operator": "channel", "operand": "general"},
        ]
    }

    request_target_channel: dict[str, Any] = {
        "anchor": "newest",
        "num_before": 1,
        "num_after": 0,
        "narrow": [
            {"operator": "sender", "operand": self_email},
            {"operator": "channel", "operand": "test"},
        ]
    }

    source_last_message = client.get_messages(request_source_channel)
    target_last_message = client.get_messages(request_target_channel)

    hookered_data = {
        "source_message": source_last_message.get('messages')[0],
        "target_message": target_last_message.get('messages')[0],
    }
    print("-" *100)
    print(f"{hookered_data}")

    if source_last_message.get('result', "error") == "success" and target_last_message.get('result', "error") == "success":
        handler(hookered_data, None)
    else:
        return None