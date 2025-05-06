#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *
import re


def handle_storage_update_notetypes(context: Context,message,data) -> Status:
    status = Status()
    notetype : Notetype = None
    time.sleep(0.3)
    context.update_database()
    for i in AnkiObjMap().array_by_type("notetype"):
        if i.name == tp.name:
            notetype = i
            if not context.monitor.is_event_triggered(EventAddNotetype()):
                status.emit(EventAddNotetype())
            break
    if notetype is None:
        return None
    else:
        context._tracking_id = notetype.id

    if len(notetype.fields) == 3 and  notetype.fields[2] == "Note":
        status.emit(EventNotetypeFieldCorrect())
    front_side_pattern = r'\{\{#Note\}\}.*color:blue.*\{\{/Note\}\}.*\{\{正面\}\}.*\{\{#Note\}\}.*</span>.*\{\{/Note\}\}'
    back_side_pattern = r'.*\{\{背面\}\}.*\{\{#Note\}\}.*</span>.*\{\{/Note\}\}'
    if  len(notetype.templates) == 2:
        if re.findall(front_side_pattern,notetype.templates[0],re.DOTALL):
            print("Front side pattern matched") 
        else:
            print(notetype.templates[0])
            return status
        if re.findall(back_side_pattern,notetype.templates[1],re.DOTALL):
            print("Back side pattern matched") 
        else:
            print(notetype.templates[1])
            return status
        status.emit(EventNotetypeTemplateCorrect())

    return status

def handle_storage_add_card(context: Context,message,data) -> Status:
    status = Status()
    print("ok!")
    if not context.monitor.is_event_triggered(EventNotetypeTemplateCorrect()):
        return None
    context.update_database()
    latest : Card = sorted(context.cards,key=lambda x: x.mod,reverse=True)[0]
    note :Note = latest.get_note()
    if note.mid != context._tracking_id:
        print(f"Error: Latest card's note {note.mid} does not match the tracking id({context._tracking_id}).")
        return None
    status.emit(EventAddCardSuccess())
    status.mark_progress()

    if len(note.fields) == 3 and note.fields[0] == tp.first_field and note.fields[1] == tp.second_field and note.fields[2] == tp.third_field:
        status.emit(EventCardCorrect())
    return status
    

TRACE_HANDLERS = {
    "storage_update_notetypes" : handle_storage_update_notetypes,
    "storage_add_card" : handle_storage_add_card
}   
dependency_graph = {
    add_notetype_ : [],
    notetype_field_correct_ : [add_notetype_],
    notetype_template_correct_ : [notetype_field_correct_],
    add_card_success_ : [notetype_template_correct_],
    card_correct_ : [add_card_success_],
}
finished_list = [
    card_correct_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)