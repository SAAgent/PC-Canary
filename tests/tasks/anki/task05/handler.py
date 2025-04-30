#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_card(context: Context,message,data) -> Status:
    context.update_database()
    latest : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest.get_note()
    status = Status(status=StatusType.PROGRESS)
    status.emit(EventCardAdded())
    if len(note.fields) == 2 and note.fields[0] == tp.first_field and note.fields[1] == tp.second_field:
        deck = latest.get_deck()
        if deck and deck.name == tp.deck_name:
            status.emit(EventCardCorrect())
        else:
            status.emit(EventCardWrong(tp.deck_name,deck.name))
    else:
        status.emit(EventCardWrong(note.fields,f"[{tp.first_field} {tp.second_field}]"))

    return status
      

def handle_service_undo(context: Context,message,data) -> Status:
    time.sleep(1)
    context.update_database()
    status = Status()
    
    if not any([(len(note.fileds) == 2 and note.field[0] == tp.first_field and 
            note.fields[1] == tp.second_field) for note in AnkiObjMap().array_by_type("note")]):
        status.emit(EventUndo())
    return status

TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card,
    "service_undo" : handle_service_undo,
}   

dependency_graph = {
    card_added_ : [],
    card_correct_ : [card_added_],
    card_wrong_ : [card_added_],
    undo_ : [card_correct_]
}
finished_list = [
    undo_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)