import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

class EventDeckAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("deck_added", value)


    def describe(self):
        return "数据库中添加成功"
    
class EventDeckRemoved(FridaEvent):

    def __init__(self,value=True):
        super().__init__("deck_removed", value)


    def describe(self):
        return "数据库中删除成功"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    deck_name : str
tp = TaskParameters(**{'deck_name': 'ielts'})
