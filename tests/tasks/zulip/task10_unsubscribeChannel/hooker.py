from typing import Dict, Any, Callable
import zulip

client = zulip.Client(config_file="~/zuliprc")

def inspector_on_completion(handler: Callable[[Dict[str, Any], Any], None]):
    """
    在任务结束时调用, handler是用来处理获取得到的数据, 最终会调用到handler.py中的message_handler函数
    """

    # 获取消息, 然后使用handler处理消息
    result = client.get_subscriptions()
    if result.get('result', "error") == "success":
        print(f"-"*100)
        print(f"subscriptions:{result.get('subscriptions')}")
        handler({
            "subscriptions": result.get('subscriptions')
        }, None)
    else:
        return None