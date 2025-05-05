import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

card_added_ : str = "card_added"  # 添加了卡片
tag_added_ : str = "tag_added"  # 添加了标签

class EventCardAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_added", value)


    def describe(self):
        return "添加了卡片"
    
class EventTagAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("tag_added", value)


    def describe(self):
        return "添加了标签"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    tag_name : str
tp = TaskParameters(**{'tag_name': 'cs'})
