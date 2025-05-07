import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

add_deck_ : str = "add_deck"  # 添加成功
move_card_ : str = "move_card"  # 移动一个卡片
move_all_cards_ : str = "move_all_cards"  # 移动完所有卡片

class EventAddDeck(FridaEvent):

    def __init__(self,value=True):
        super().__init__("add_deck", value)


    def describe(self):
        return "添加成功"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

class EventMoveCard(FridaEvent):

    def __init__(self,value=True):
        super().__init__("move_card", value)


    def describe(self):
        return "移动一个卡片"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 2

class EventMoveAllCards(FridaEvent):

    def __init__(self,value=True):
        super().__init__("move_all_cards", value)


    def describe(self):
        return "移动完所有卡片"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 3

from dataclasses import dataclass
@dataclass
class TaskParameters:
    tag_name : str
tp = TaskParameters(**{'tag_name': 'cs'})
