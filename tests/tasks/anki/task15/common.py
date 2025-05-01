import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

delay_ : str = "delay"  # 搁置成功

class EventDelay(FridaEvent):

    def __init__(self,value=True):
        super().__init__("delay", value)


    def describe(self):
        return "搁置成功"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    tag_name : str
tp = TaskParameters(**{'tag_name': 'delay'})
