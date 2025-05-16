from typing import Dict, Any, Callable
import zulip

client = zulip.Client(config_file="~/zuliprc")

def inspector_on_completion(handler: Callable[[Dict[str, Any], Any], None]):
    """
    在任务结束时调用, handler是用来处理获取得到的数据, 最终会调用到handler.py中的message_handler函数
    """

    # 获取用户状态, 然后使用handler处理消息
    client = zulip.Client(config_file="~/zuliprc")

    # Get all channels that the user is subscribed to.
    result = client.get_subscriptions()

    if result.get('result', "error") == "success":

        subscriptions = result.get("subscriptions")
        print("-" * 100)
        print(f"{subscriptions}")
        handler({
            "subscriptions": subscriptions
        }, None)
    else:
        return None
