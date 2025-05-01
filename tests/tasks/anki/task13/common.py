import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

card_added_ : str = "card_added"  # 添加了卡片
image_added_ : str = "image_added"  # 添加了图片
card_format_correct_ : str = "card_format_correct"  # 卡片格式匹配

class EventCardAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_added", value)


    def describe(self):
        return "添加了卡片"
    
class EventImageAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("image_added", value)


    def describe(self):
        return "添加了图片"
    
class EventCardFormatCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_format_correct", value)


    def describe(self):
        return "卡片格式匹配"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    path : str
tp = TaskParameters(**{'path': '/home/agent/PC-Canary/tests/tasks/anki/task13/dog.jpg'})
