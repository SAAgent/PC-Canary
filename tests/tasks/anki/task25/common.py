import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

add_card_ : str = "add_card"  # 添加卡片
card_info_correct_ : str = "card_info_correct"  # 卡片信息正确
card_format_correct_ : str = "card_format_correct"  # 卡片数据正确
setting_correct_ : str = "setting_correct"  # 插件设置正确

class EventAddCard(FridaEvent):

    def __init__(self,value=True):
        super().__init__("add_card", value)


    def describe(self):
        return "添加卡片"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

class EventCardInfoCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_info_correct", value)


    def describe(self):
        return "卡片信息正确"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

class EventCardFormatCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_format_correct", value)


    def describe(self):
        return "卡片数据正确"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 2

class EventSettingCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("setting_correct", value)


    def describe(self):
        return "插件设置正确"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

