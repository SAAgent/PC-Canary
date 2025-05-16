import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

card_added_ : str = "card_added"  # 卡片添加
card_correct_ : str = "card_correct"  # 卡片信息正确
card_wrong_ : str = "card_wrong"  # 卡片信息错误
undo_ : str = "undo"  # 卡片撤销添加

class EventCardAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_added", value)


    def describe(self):
        return "卡片添加"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

class EventCardCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_correct", value)


    def describe(self):
        return "卡片信息正确"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 2

class EventCardWrong(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("card_wrong", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片信息错误"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

class EventUndo(FridaEvent):

    def __init__(self,value=True):
        super().__init__("undo", value)


    def describe(self):
        return "卡片撤销添加"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 3

from dataclasses import dataclass
@dataclass
class TaskParameters:
    first_field : str
    second_field : str
    deck_name : str
tp = TaskParameters(**{'first_field': 'The world is your oyster', 'second_field': 'Shakespeare', 'deck_name': '系统默认'})
