import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

add_red_flag_ : str = "add_red_flag"  # 添加一个红色旗标
add_all_red_flags_ : str = "add_all_red_flags"  # 添加完所有卡片

class EventAddRedFlag(FridaEvent):

    def __init__(self,value=True):
        super().__init__("add_red_flag", value)


    def describe(self):
        return "添加一个红色旗标"
    
class EventAddAllRedFlags(FridaEvent):

    def __init__(self,value=True):
        super().__init__("add_all_red_flags", value)


    def describe(self):
        return "添加完所有卡片"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    tag_name : str
tp = TaskParameters(**{'tag_name': 'cs'})
