#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_card(context: Context,message) -> Status:
    context.update_database()
    latest : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest.get_note()
    status = Status(status=StatusType.PROGRESS)
    status.emit(EventCardAdded())
    if len(note.fields) == 2 and note.fields[0] == tp.first_field and note.fields[1] == tp.second_field:
        status.emit(EventCorrectField())
    else:
        status.emit(EventWrongField(note.fields,f"[{tp.first_field} {tp.second_field}]"))
    deck = latest.get_deck()
    if deck and deck.name == "系统默认":
        status.emit(EventCorrectDeck())
    else:
        status.emit(EventWrongDeck("系统默认",deck.name))

    return status
      
TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card
}   
dependency_graph = {
    "card_added" : [],
    "correct_field" : ["card_added"],
    "correct_deck" : ["card_added"]
}
finished_list = [
    "correct_field","correct_deck"
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)