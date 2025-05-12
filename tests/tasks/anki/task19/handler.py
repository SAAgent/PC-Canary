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
    to_remove = []
    for nid in context._cards_to_remove:
        if nid not in notes:
            to_remove.append(nid)
            status.emit(EventRemoveNote(nid))
        else:
            print(f"nid {nid}")
    for nid in to_remove:
        context._cards_to_remove.remove(nid)
    if not context._cards_to_remove:
        status.emit(EventRemoveAllNotes())
        
    return status

def scan_remove_items(context: Context):
    context.update_database()
    cards : List[Card] = list(map(lambda c:c.nid,filter(lambda c: tp.tag_name in c.get_note().tags, AnkiObjMap().array_by_type("card"))))
    context._cards_to_remove = cards
    assert len(cards) > 0, "No cards found with the tag"
    

def handle_done(context: Context,message): 
    if not context.monitor.is_event_triggered(EventRemoveNote()) or not context.monitor.is_event_triggered(EventRemoveAllNotes()):
        return handle_service_remove_notes(context,None)

TRACE_HANDLERS = {
    "storage_remove_notes": handle_service_remove_notes,
}   
dependency_graph = {
   remove_note_ : [],
    remove_all_notes_ : [remove_note_]    
}
finished_list = [
    remove_all_notes_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list,init=scan_remove_items,done=handle_done)