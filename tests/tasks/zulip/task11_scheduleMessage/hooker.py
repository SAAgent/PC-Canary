from typing import Dict, Any, Callable
import zulip
import os
import requests

client = zulip.Client(config_file="~/zuliprc")

def inspector_on_completion(handler: Callable[[Dict[str, Any], Any], None]):
    """
    在任务结束时调用, handler是用来处理获取得到的数据, 最终会调用到handler.py中的message_handler函数
    """

    config_file_path = os.path.expanduser("~/zuliprc")
    with open(config_file_path, "r") as file:
        lines = file.readlines()

    # 提取email, api_key, site
    self_email = None
    self_api_key = None
    self_site = None
    


    for line in lines:
        if line.startswith("email="):
            self_email = line.split("=")[1].strip()
        elif line.startswith("key="):
            self_api_key = line.split("=")[1].strip()
        elif line.startswith("site="):
            self_site = line.split("=")[1].strip()

    print("-"*100)
    print(f"email={self_email}, api_key={self_api_key}, site={self_site}")
    

    schedule_message_request_url = f'{self_site}/api/v1/scheduled_messages'
    response = requests.get(schedule_message_request_url, auth=(self_email, self_api_key))

    print("-"*100)
    print(response)

    if response.status_code == 200:
        result = response.json()
        print("-"*100)
        print(f"{result}")
        if result.get('result', "error") == "success":
            handler({
                "scheduled_messages": result.get('scheduled_messages')
            }, None)
        else:
            return None
    else:
        return None
