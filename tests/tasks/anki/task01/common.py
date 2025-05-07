import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

card_added_ : str = "card_added"  # 数据库中出现卡片
correct_field_ : str = "correct_field"  # 卡片数据匹配
wrong_field_ : str = "wrong_field"  # 卡片数据不匹配
correct_deck_ : str = "correct_deck"  # 卡片Deck正确
wrong_deck_ : str = "wrong_deck"  # 卡片Deck不匹配

class EventCardAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_added", value)


    def describe(self):
        return "数据库中出现卡片"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

class EventCorrectField(FridaEvent):

    def __init__(self,value=True):
        super().__init__("correct_field", value)


    def describe(self):
        return "卡片数据匹配"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 2

class EventWrongField(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("wrong_field", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片数据不匹配"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

class EventCorrectDeck(FridaEvent):

    def __init__(self,value=True):
        super().__init__("correct_deck", value)


    def describe(self):
        return "卡片Deck正确"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

class EventWrongDeck(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("wrong_deck", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片Deck不匹配"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

from dataclasses import dataclass
@dataclass
class TaskParameters:
    first_field : str
    second_field : str
tp = TaskParameters(**{'first_field': 'Hello', 'second_field': 'World'})
