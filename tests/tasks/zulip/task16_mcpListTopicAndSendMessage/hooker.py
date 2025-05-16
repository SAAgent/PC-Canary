from typing import Dict, Any, Callable
import zulip

client = zulip.Client(config_file="~/zuliprc")

def inspector_on_completion(handler: Callable[[Dict[str, Any], Any], None]):
    """
    在任务结束时调用, handler是用来处理获取得到的数据, 最终会调用到handler.py中的message_handler函数
    """

    result = client.get_profile()
    self_email = result.get('email', None)
    request: dict[str, Any] = {
        "anchor": "newest",
        "num_before": 1,
        "num_after": 0,
        "narrow": [
            {"operator": "sender", "operand": self_email},
        ]
    }

    channel_name = "general"
    channel_id = client.get_stream_id(channel_name).get("stream_id", None)
    topics = client.get_stream_topics(channel_id).get("topics", [])
    target_message = " ".join([topic['name'] for topic in topics])

    print("-"*100)
    print(f"channel_name: {channel_name},channel_id: {channel_id}")
    print(f"topics: {topics}")

    last_message = client.get_messages(request)
    hookered_data = {
        "target_message": target_message,
        "last_message": last_message.get('messages')[0],
    }

    if last_message.get('result', "error") == "success":
        handler(hookered_data, None)
    else:
        return None