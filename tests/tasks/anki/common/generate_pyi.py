import json
import os
from typing import Any, Dict, Tuple

# 解析JSON数据
def parse_json(json_data: str) -> Dict:
    return json.loads(json_data)

# 为每个事件生成一个类定义模板
def generate_event_classes(data: Dict) -> str:
    template = """import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *\n\n"""
    if "events" in data:

        for event_key, value in data["events"].items():
            template += f"{event_key}_ : str = \"{event_key}\"  # {value["description"]}\n"
        for event_key, value in data["events"].items():
            description = value["description"]
            is_key_event = value["is_key_step"]
            key_step_index = value.pop("key_step_index", 0)
            class_name = ''.join(word.capitalize() for word in event_key.split('_'))
            template += f"""
class Event{class_name}(FridaEvent):
"""
            if "wrong" not in event_key:
                template += f"""
    def __init__(self,value=True):
        super().__init__(\"{event_key}\", value)

"""
            else:
               template += f"""
    def __init__(self,get="",expect=""):
        super().__init__(\"{event_key}\", f"got {{get}}, expect {{expect}}")

"""
            template+=f"""
    def describe(self):
        return "{description}"
    
    def is_key_event(self):
        return {is_key_event}

    def key_index(self):
        return {key_step_index}
"""
    template += "\n"
    if "task_parameters" in data and data["task_parameters"]:
        template += f"""from dataclasses import dataclass
@dataclass
class TaskParameters:
"""
        for task_key in data["task_parameters"].keys():
            template += f"    {task_key} : str\n"
        template += f"tp = TaskParameters(**{repr(data['task_parameters'])})\n"
            
    # generate event name constant
    
    if "sql_path" not in data:
        raise RuntimeError("sql_path not found in config.json")
    return template

# 遍历../目录的每个文件夹，如果含有config.json，那么根据其中的config.json生成一个文件，写入到该文件夹中的events.pyi中
def generate_event_files(root_dir: str) -> None:
    for foldername, _ , filenames in os.walk(root_dir):
        if 'config.json' in filenames:
            config_path = os.path.join(foldername, 'config.json')
            with open(config_path, 'r') as config_file:
                template = generate_event_classes(json.load(config_file))
            if template:
                with open(os.path.join(foldername, 'common.py'), 'w') as events_file:
                    events_file.write(template)
            print(f"Generated events.pyi in {foldername}")
generate_event_files("../")