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
    if len(notetype.fields) == 3 and notetype.fields[0] == "question" and notetype.fields[1] == "short_answer" and notetype.fields[2] == "long_answer":
        status.emit(EventNotetypeFieldCorret())
   
    pattern = r'\{\{FrontSide\}\}.+\<div.+color:red.+\>\{\{short_answer\}\}.+\{\{long_answer\}\}'
    if  len(notetype.templates) == 2:
        if re.match(pattern,notetype.templates[1],re.DOTALL):
            status.emit(EventNotetypeFormatCorrect())

    return status


TRACE_HANDLERS = {
    "storage_update_notetypes" : handle_storage_update_notetypes
}   
dependency_graph = {
    add_notetype_ : [],
    notetype_field_corret_ : [add_notetype_],
    notetype_format_correct_ : [add_notetype_],
}
finished_list = [
    notetype_field_corret_,notetype_format_correct_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)