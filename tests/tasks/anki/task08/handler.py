#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import datetime
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_card(context: Context,message) -> Status:
    context.update_database()
    latest_card : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest_card.get_note()
    status = Status()
    if len(note.fields) == 2:
        status.mark_progress()
        status.emit(EventCardAdded())
    
    if tp.tag_name in note.tags:
        status.emit(EventTagAdded())
        
    return status
TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card,
}   
dependency_graph = {
    card_added_ : [],
    tag_added_ : [card_added_]
}
finished_list = [
   tag_added_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)