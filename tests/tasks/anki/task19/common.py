import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../common')))
from exanki import *

remove_note_ : str = "remove_note"  # 删除一个卡片
remove_all_notes_ : str = "remove_all_notes"  # 删除了所有卡片

class EventRemoveNote(FridaEvent):

    def __init__(self,value=True):
        super().__init__("remove_note", value)


    def describe(self):
        return "删除一个卡片"
    
class EventRemoveAllNotes(FridaEvent):

    def __init__(self,value=True):
        super().__init__("remove_all_notes", value)


    def describe(self):
        return "删除了所有卡片"
    
from dataclasses import dataclass
@dataclass
class TaskParameters:
    tag_name : str
tp = TaskParameters(**{'tag_name': 'suspend'})
