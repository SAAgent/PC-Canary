#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import datetime
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_service_search_cards(context: Context,message) -> Status:
    status = Status()
    status.emit(EventSearchCardCalled())
    return status

def handle_storage_update_card(context: Context,message) -> Status:    
    if not context.should_event_trigger(EventUpdateCardExpirationDate()):
        return None
    context.update_database()
    status = Status()
    cards : List[Card] = list(filter(lambda x: any([tp.search_keyword in field for field in x.get_note().fields]),AnkiObjMap().array_by_type("card")))
    due_days = ((datetime.datetime.now() + datetime.timedelta(days=int(tp.due_days))-context.col.crt)).days
    if all([card.type == CardType.REVIEW and card.due == due_days for card in cards]):
        status.emit(EventUpdateCardExpirationDate())
    return status

def handle_storage_add_card(context: Context,message) -> Status:
    context.update_database()
    latest : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest.get_note()
    status = Status(status=StatusType.PROGRESS)
    if len(note.fields) == 2 and tp.search_keyword in note.fields[0]  or tp.search_keyword in  note.fields[1]:
        status.emit(EventCardAdded())

    return status
TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card,
    "service_serach_cards" : handle_service_search_cards,
    "storage_update_card" : handle_storage_update_card,
}   
dependency_graph = {
    card_added_ : [],
    search_card_called_ : [card_added_],
    update_card_expiration_date_ : [search_card_called_]
}
finished_list = [
    update_card_expiration_date_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)