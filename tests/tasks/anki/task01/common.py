import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

class EventCardAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_added", value)


    def describe(self):
        return "数据库中出现卡片"
    
class EventCorrectField(FridaEvent):

    def __init__(self,value=True):
        super().__init__("correct_field", value)


    def describe(self):
        return "卡片数据匹配"
    
class EventWrongField(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("wrong_field", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片数据不匹配"
    
class EventCorrectDeck(FridaEvent):

    def __init__(self,value=True):
        super().__init__("correct_deck", value)


    def describe(self):
        return "卡片Deck正确"
    
class EventWrongDeck(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("wrong_deck", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片Deck不匹配"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    first_field : str
    second_field : str
tp = TaskParameters(**{'first_field': 'Hello', 'second_field': 'World'})
