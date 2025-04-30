import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

card_added_ : str = "card_added"  # 数据库中出现卡片
correct_field_ : str = "correct_field"  # 卡片数据匹配
wrong_field_ : str = "wrong_field"  # 卡片数据不匹配
correct_format_ : str = "correct_format"  # 卡片格式匹配
wrong_format_ : str = "wrong_format"  # 卡片格式不匹配

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
    
class EventCorrectFormat(FridaEvent):

    def __init__(self,value=True):
        super().__init__("correct_format", value)


    def describe(self):
        return "卡片格式匹配"
    
class EventWrongFormat(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("wrong_format", f"got {get}, expect {expect}")


    def describe(self):
        return "卡片格式不匹配"
    
