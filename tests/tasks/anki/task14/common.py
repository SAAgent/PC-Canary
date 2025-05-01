import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

card_added_ : str = "card_added"  # 添加了卡片
search_card_called_ : str = "search_card_called"  # 调用了查找函数
replace_card_success_ : str = "replace_card_success"  # 调用了替换函数

class EventCardAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_added", value)


    def describe(self):
        return "添加了卡片"
    
class EventSearchCardCalled(FridaEvent):

    def __init__(self,value=True):
        super().__init__("search_card_called", value)


    def describe(self):
        return "调用了查找函数"
    
class EventReplaceCardSuccess(FridaEvent):

    def __init__(self,value=True):
        super().__init__("replace_card_success", value)


    def describe(self):
        return "调用了替换函数"
    
