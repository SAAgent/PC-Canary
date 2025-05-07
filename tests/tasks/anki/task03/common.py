import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

deck_added_ : str = "deck_added"  # 数据库中添加成功
deck_removed_ : str = "deck_removed"  # 数据库中删除成功

class EventDeckAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("deck_added", value)


    def describe(self):
        return "数据库中添加成功"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

class EventDeckRemoved(FridaEvent):

    def __init__(self,value=True):
        super().__init__("deck_removed", value)


    def describe(self):
        return "数据库中删除成功"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 2

from dataclasses import dataclass
@dataclass
class TaskParameters:
    deck_name : str
tp = TaskParameters(**{'deck_name': 'ielts'})
