import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

deck_added_ : str = "deck_added"  # 数据库中出现卡片
correct_deck_ : str = "correct_deck"  # 卡片Deck正确
wrong_deck_ : str = "wrong_deck"  # 卡片Deck不正确

class EventDeckAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("deck_added", value)


    def describe(self):
        return "数据库中出现卡片"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

class EventCorrectDeck(FridaEvent):

    def __init__(self,value=True):
        super().__init__("correct_deck", value)


    def describe(self):
        return "卡片Deck正确"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 2

class EventWrongDeck(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("wrong_deck", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片Deck不正确"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

from dataclasses import dataclass
@dataclass
class TaskParameters:
    deck_name : str
tp = TaskParameters(**{'deck_name': 'ielts'})
