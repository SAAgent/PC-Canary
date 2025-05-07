#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_deck(context: Context,message) -> Status:
    context.update_database()
    deck : Deck = sorted(AnkiObjMap().array_by_type("deck"),key=lambda x: x.mtime,reverse=True)
    status = Status()
    if deck[0].name == tp.deck_name:
        status.emit(EventDeckAdded())   
        status.mark_progress()
    return status

def handle_storage_remove_deck(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    if all([deck.name != tp.deck_name for deck in AnkiObjMap().array_by_type("deck")]):
        status.emit(EventDeckRemoved())   
        status.mark_progress()
    return status


def handle_service_undo(context: Context,message) -> Status:
    time.sleep(1)
    context.update_database()
    status = Status()
    if any([deck.name == tp.deck_name for deck in AnkiObjMap().array_by_type("deck")]):
        status.emit(EventUndoRemoved())
    return status

TRACE_HANDLERS = {
    "storage_remove_deck": handle_storage_remove_deck,
    "storage_add_deck": handle_storage_add_deck,
    "service_undo" : handle_service_undo,
}   
dependency_graph = {
    deck_added_ : [],
    deck_removed_ : [deck_added_],
    undo_removed_ : [deck_removed_]
}
finished_list = [
    undo_removed_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)