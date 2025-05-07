#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *
import json
import re

def handle_storage_add_note(context: Context,message) -> Status:
    status = Status()
    context.update_database()

    if not context.monitor.is_event_triggered(EventSettingCorrect()) and os.path.exists("/home/agent/.local/share/Anki2/addons21/1990296174/meta.json"):
        print("checking")
        with open("/home/agent/.local/share/Anki2/addons21/1990296174/meta.json") as f:
            config = json.load(f)
            if config["config"]["showHintsForPseudoClozes"] == False:
                status.emit(EventSettingCorrect())
    
    latest : Note = sorted(context.notes,key=lambda x: x.mod,reverse=True)[0]
    if latest.mid == context._ntid:
        status.emit(EventAddCard())

        content = latest.fields[0]
        pattern = r"\{\{c\d+::(.*?)\}\}"

        result = re.sub(pattern, r"\1", content).replace("#","")
        if result == "The quick brown fox jumps over the lazy dog.":
            status.emit(EventCardInfoCorrect())
        
        
        pattern = r"\{\{c\d+::(.*?)\}\}"
        result = re.findall(pattern, content)
        if len(result) == 4 and result[0] == "brown" and result[1] == "fox" and result[2] == "#lazy" and result[3] == "dog":
            status.emit(EventCardFormatCorrect())
    return status
def init(context : Context):
    context.update_database()
    for nt in context.notetypes:
        if "Enhanced Cloze" in nt.name:
            context._ntid = nt.id
    if not hasattr(context,"_ntid"):
        raise "no Enhanced Cloze notetype found. Try install Enhanced Cloze plugin with code(1990296174)."
    context.log("info",f"Enhanced Cloze notetype found with id {context._ntid}")
       

TRACE_HANDLERS = {
    "storage_add_note" : handle_storage_add_note,
}   

dependency_graph = {
    add_card_ : [],
    card_info_correct_ : [add_card_],
    card_format_correct_ : [add_card_],
    setting_correct_ : []
}
finished_list = [
    setting_correct_,card_format_correct_,card_info_correct_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list,init=init)
