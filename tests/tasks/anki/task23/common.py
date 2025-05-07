import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

add_notetype_ : str = "add_notetype"  # 添加成功
notetype_field_corret_ : str = "notetype_field_corret"  # 字段名称正确
notetype_field_wrong_ : str = "notetype_field_wrong"  # 字段名称错误
notetype_format_correct_ : str = "notetype_format_correct"  # 字段格式正确
notetype_format_wrong_ : str = "notetype_format_wrong"  # 字段格式错误

class EventAddNotetype(FridaEvent):

    def __init__(self,value=True):
        super().__init__("add_notetype", value)


    def describe(self):
        return "添加成功"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

class EventNotetypeFieldCorret(FridaEvent):

    def __init__(self,value=True):
        super().__init__("notetype_field_corret", value)


    def describe(self):
        return "字段名称正确"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 2

class EventNotetypeFieldWrong(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("notetype_field_wrong", f"got {get}, expect {expect}")


    def describe(self):
        return "字段名称错误"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

class EventNotetypeFormatCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("notetype_format_correct", value)


    def describe(self):
        return "字段格式正确"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

class EventNotetypeFormatWrong(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("notetype_format_wrong", f"got {get}, expect {expect}")


    def describe(self):
        return "字段格式错误"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

from dataclasses import dataclass
@dataclass
class TaskParameters:
    name : str
tp = TaskParameters(**{'name': 'simple'})
