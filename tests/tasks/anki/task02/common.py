import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

class EventDeckAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("deck_added", value)


    def describe(self):
        return "数据库中出现卡片"
    
class EventCorrectDeck(FridaEvent):

    def __init__(self,value=True):
        super().__init__("correct_deck", value)


    def describe(self):
        return "卡片Deck正确"
    
class EventWrongDeck(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("wrong_deck", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片Deck不正确"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    deck_name : str
tp = TaskParameters(**{'deck_name': 'ielts'})
