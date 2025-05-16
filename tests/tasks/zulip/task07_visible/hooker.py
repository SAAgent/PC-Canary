from typing import Dict, Any, Callable
import zulip

client = zulip.Client(config_file="~/zuliprc")

def inspector_on_completion(handler: Callable[[Dict[str, Any], Any], None]):
    """
    在任务结束时调用, handler是用来处理获取得到的数据, 最终会调用到handler.py中的message_handler函数
    """

    profile = client.get_profile()
    self_email = profile.get('email', None)
    result = client.get_user_presence(self_email)

    print("-" * 100)
    print(f"email:{self_email};online statsus:{result}")
    if result.get('result', "error") == "success":
        handler({
            "presence": result.get('presence')
        }, None)
    else:
        return None
