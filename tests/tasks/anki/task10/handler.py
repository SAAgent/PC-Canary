#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *
import re

def handle_storage_add_card(context: Context,message) -> Status:
    context.update_database()
    latest_card : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest_card.get_note()
    status = Status()
    status.emit(EventCardAdded())
    s = note.fields[0].replace("&nbsp"," ")
    if len(note.fields) == 2 and re.findall("The\s+capital\s+of\s+China\s+is\s+\{\{c1::Beijing\}\}",s):
        status.emit(EventCardFormatCorrect())
    else:
        status.emit(EventCardFormatWrong(note.fields[0],'The capital of China is&nbsp;{{c1::Beijing}}'))
    return status
TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card,
}   
dependency_graph = {
    card_added_ : [],
    card_format_correct_ : [card_added_]
}
finished_list = [
    card_format_correct_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)