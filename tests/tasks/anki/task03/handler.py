#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_deck(context: Context,message,data) -> Status:
    context.update_database()
    deck : Deck = sorted(AnkiObjMap().array_by_type("deck"),key=lambda x: x.mtime,reverse=True)
    status = Status()
    if deck[0].name == tp.deck_name:
        status.emit(EventDeckAdded())   
        context.is_deck_created = True
        status.mark_progress()
    return status

def handle_storage_remove_deck(context: Context,message,data) -> Status:
    context.update_database()
    status = Status()
    if all([deck.name != tp.deck_name for deck in AnkiObjMap().array_by_type("deck")]):
        if hasattr(context,"is_deck_created"):
            status.mark_success()
    return status

TRACE_HANDLERS = {
    "storage_remove_deck": handle_storage_remove_deck,
    "storage_add_deck": handle_storage_add_deck,
}   
dependency_graph = {
    "deck_added" : [],
    "deck_removed" : ["deck_added"]
}
finished_list = [
    "deck_removed"
]
bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)