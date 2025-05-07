#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_service_remove_notes(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    notes : set[int] = set(map(lambda note:note.nid,AnkiObjMap().array_by_type("note")))
    print(notes)
    for nid in context._cards_to_remove:
        if nid not in notes:
            context._cards_to_remove.remove(nid)
            status.emit(EventRemoveNote())
            break
    if not context._cards_to_remove:
        status.emit(EventRemoveAllNotes())
        
    return status

def scan_remove_items(context: Context):
    context.update_database()
    cards : List[Card] = list(map(lambda c:c.nid,filter(lambda c: tp.tag_name in c.get_note().tags, AnkiObjMap().array_by_type("card"))))
    context._cards_to_remove = cards
    assert len(cards) > 0, "No cards found with the tag"
    

TRACE_HANDLERS = {
    "service_remove_notes": handle_service_remove_notes,
}   
dependency_graph = {
   remove_note_ : [],
    remove_all_notes_ : [remove_note_]    
}
finished_list = [
    remove_all_notes_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list,init=scan_remove_items)