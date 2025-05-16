from typing import Dict, Any, Callable
import zulip

client = zulip.Client(config_file="~/zuliprc")

def inspector_on_completion(handler: Callable[[Dict[str, Any], Any], None]):
    """
    在任务结束时调用, handler是用来处理获取得到的数据, 最终会调用到handler.py中的message_handler函数
    """

    result = client.get_profile()
    
    print("-" * 100)
    print(f"result:{result}")
    
    self_id = result.get('user_id', None)

    result = client.call_endpoint(
        url=f"/users/{self_id}/status",
        method="GET",
    )
    print("-" * 100)
    print(f"user_id:{self_id};statsus result:{result}")

    if result.get('result', "error") == "success":
        handler({
            "status": result.get('status')
        }, None)
    else:
        return None
