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
    self_id = result.get('user_id', None)

    request: dict[str, Any] = {
        "anchor": "newest",
        "num_before": 1,
        "num_after": 0,
        "narrow": [
            {"operator": "sender", "operand": self_email},
        ]
    }

    # 获取最新的消息id
    last_message = client.get_messages(request)
    last_message = last_message.get('messages')[-1]
    lastest_message_id = last_message.get('id')

    last_message = client.get_messages(request)

    hookered_data = {
        "message_id": lastest_message_id,
        "last_message": last_message.get('messages')[-1],
        "self_id": self_id,
    }

    print(f"-" * 100)
    print(f"{hookered_data}")

    if last_message.get('result', "error") == "success":
        handler(hookered_data, None)
    else:
        return None