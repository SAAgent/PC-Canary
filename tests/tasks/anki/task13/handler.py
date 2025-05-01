#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_card(context: Context,message,data) -> Status:
    context.update_database()
    latest_card : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest_card.get_note()
    status = Status()
    status.emit(EventCardAdded())
    if len(note.fields) == 2 and "What is this?" in note.fields[0] and \
        tp.path.split('/')[-1] in note.fields[0] and note.fields[1] == "dog":
        status.emit(EventCardFormatCorrect())
    else:
        status.mark_error()
    return status

def handle_add_media_file(context: Context,message,data) -> Status:
    status = Status()
    status.emit(EventImageAdded())
    status.mark_progress()
    return status

TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card,
    "service_add_media_file" : handle_add_media_file,
}   

dependency_graph = {
    image_added_: [],
    card_added_ : [image_added_],
    card_format_correct_ : [card_added_]
}
finished_list = [
   card_added_ 
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)