import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

set_sucess_ : str = "set_sucess"  # 设置成功
set_wrong_ : str = "set_wrong"  # 设置错误

class EventSetSucess(FridaEvent):

    def __init__(self,value=True):
        super().__init__("set_sucess", value)


    def describe(self):
        return "设置成功"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

class EventSetWrong(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("set_wrong", f"got {get}, expect {expect}")


    def describe(self):
        return "设置错误"
    
    def is_key_event(self):
        return False

    def key_index(self):
        return 0

from dataclasses import dataclass
@dataclass
class TaskParameters:
    time : str
tp = TaskParameters(**{'time': '1'})
