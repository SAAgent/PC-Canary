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
    
class EventSetWrong(FridaEvent):

    def __init__(self,get="",expect=""):
        super().__init__("set_wrong", f"got {get}, expect {expect}")


    def describe(self):
        return "设置错误"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    time : str
tp = TaskParameters(**{'time': '15'})
