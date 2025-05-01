import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

card_added_ : str = "card_added"  # 添加了卡片
card_format_correct_ : str = "card_format_correct"  # 卡片格式匹配
card_format_wrong_ : str = "card_format_wrong"  # 卡片格式不匹配

class EventCardAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_added", value)


    def describe(self):
        return "添加了卡片"
    
class EventCardFormatCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_format_correct", value)


    def describe(self):
        return "卡片格式匹配"
    
class EventCardFormatWrong(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("card_format_wrong", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片格式不匹配"
    
