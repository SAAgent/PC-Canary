import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

clear_unused_tags_ : str = "clear_unused_tags"  # 删除所有未使用的标签

class EventClearUnusedTags(FridaEvent):

    def __init__(self,value=True):
        super().__init__("clear_unused_tags", value)


    def describe(self):
        return "删除所有未使用的标签"
    
    def is_key_event(self):
        return True

    def key_index(self):
        return 1

