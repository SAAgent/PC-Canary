from typing import Dict, Any, Callable
import zulip

client = zulip.Client(config_file="~/zuliprc")

def inspector_on_completion(handler: Callable[[Dict[str, Any], Any], None]):
    """
    在任务结束时调用, handler是用来处理获取得到的数据, 最终会调用到handler.py中的message_handler函数
    """
    # 获取消息, 然后使用handler处理消息
    stream_result = client.get_streams()
    user_result = client.get_members()
    if stream_result.get('result', "error") == "success" and user_result.get('result', 'error') == 'success':
        streams = stream_result.get('streams')
        stream_info = []
        for i in streams:
            s = {}
            s['name'] = i['name']
            s['description'] = i['description']
            result = client.get_subscribers(stream=i['name'])
            if result.get('result', "error") == 'success':
                s['count'] = len(result.get('subscribers'))
            else:
                return None
            stream_info.append(s)
        handler({
            "streams": stream_info,
            "members": len(user_result.get('members'))
        }, None)
    else:
        return None