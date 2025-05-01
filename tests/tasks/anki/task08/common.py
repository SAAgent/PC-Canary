import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

card_added_ : str = "card_added"  # 数据库中出现卡片
search_card_called_ : str = "search_card_called"  # 调用了查找函数
update_card_expiration_date_ : str = "update_card_expiration_date"  # 更新了卡片过期日期

class EventCardAdded(FridaEvent):

    def __init__(self,value=True):
        super().__init__("card_added", value)


    def describe(self):
        return "数据库中出现卡片"
    
class EventSearchCardCalled(FridaEvent):

    def __init__(self,value=True):
        super().__init__("search_card_called", value)


    def describe(self):
        return "调用了查找函数"
    
class EventUpdateCardExpirationDate(FridaEvent):

    def __init__(self,value=True):
        super().__init__("update_card_expiration_date", value)


    def describe(self):
        return "更新了卡片过期日期"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    search_keyword : str
    due_days : str
tp = TaskParameters(**{'search_keyword': 'computer', 'due_days': '4'})
