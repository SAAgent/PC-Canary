#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_service_search_cards(context: Context,message) -> Status:
    status = Status()
    status.emit(EventSearchCardCalled())
    return status

# def handle_service_find_and_replace(context: Context,message) -> Status:    
#     if not context.should_event_trigger(EventSearchCardCalled()):
#         return None
#     context.update_database()
#     status = Status()
#     cards : List[Card] = list(filter(lambda card: card.cid in context.cards_prepare_to_check ,AnkiObjMap().array_by_type("card")))
#     if all(["Where" in " ".join(card.get_note().fields) for card in cards]):
#         status.emit(EventReplaceCardSuccess())
#     return status

def handle_storage_add_card(context: Context,message) -> Status:
    context.update_database()
    cards : List[Card] = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)
    note = cards[0].get_note()
    status = Status()
    print("aaa")
    if len(note.fields) == 2 and "What" in note.fields[0]:
        status.emit(EventCardAdded())
        status.mark_progress()
        context.cards_prepare_to_check = list(map(lambda c: c.cid,filter(lambda c:"What" in c.get_note().fields[0],cards)))
        print(context.cards_prepare_to_check)

    return status

def handle_storage_update_note(context: Context,message) -> Status:
    if not context.should_event_trigger(EventSearchCardCalled()):
        return None
    context.update_database()
    status = Status()
    cards : List[Card] = list(filter(lambda card: card.cid in context.cards_prepare_to_check ,AnkiObjMap().array_by_type("card")))
    if all(["Where" in " ".join(card.get_note().fields) for card in cards]):
        status.emit(EventReplaceCardSuccess())
    return status

TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card,
    "service_serach_cards" : handle_service_search_cards,
    # "service_find_and_replace" : handle_service_find_and_replace,
    "storage_update_note" : handle_storage_update_note,
}   
dependency_graph = {
    card_added_ : [],
    search_card_called_ : [card_added_],
    replace_card_success_ : [search_card_called_]
}
finished_list = [
    replace_card_success_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)