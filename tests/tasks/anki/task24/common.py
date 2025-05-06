import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

add_notetype_ : str = "add_notetype"  # 添加成功
notetype_field_correct_ : str = "notetype_field_correct"  # 字段正确
notetype_template_correct_ : str = "notetype_template_correct"  # 模板正确
add_card_success_ : str = "add_card_success"  # 添加卡片成功
card_correct_ : str = "card_correct"  # 卡片内容正确

class EventAddNotetype(FridaEvent):

    def __init__(self,value=True):
        super().__init__("add_notetype", value)


    def describe(self):
        return "添加成功"
    
class EventNotetypeFieldCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("notetype_field_correct", value)


    def describe(self):
        return "字段正确"
    
class EventNotetypeTemplateCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("notetype_template_correct", value)


    def describe(self):
        return "模板正确"
    
class EventAddCardSuccess(FridaEvent):

    def __init__(self,value=True):
        super().__init__("add_card_success", value)


    def describe(self):
        return "添加卡片成功"
    
class EventCardCorrect(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_correct", value)


    def describe(self):
        return "卡片内容正确"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    name : str
    filed_name : str
    first_field : str
    second_field : str
    third_field : str
tp = TaskParameters(**{'name': 'simple2', 'filed_name': 'Note', 'first_field': 'The quick brown fox jumps over the lazy dog.', 'second_field': 'test', 'third_field': 'note'})
