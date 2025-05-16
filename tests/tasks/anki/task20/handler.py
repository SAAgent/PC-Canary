#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_deck(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    decks : List[int] = list(filter(lambda deck:deck.name == tp.tag_name,context.decks))
    if len(decks):
        deck = decks[0]
        cards :List[Card] = list(filter(lambda c:tp.tag_name in c.get_note().tags,AnkiObjMap().array_by_type("card")))
        context._this_did = deck.did
        context._number_of_card_with_tag = len(cards)
        context._counter = 0
        status.emit(EventAddDeck())
    return status

def handle_storage_update_card(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    card : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    did : List[int] = list(map(lambda deck:deck.did,filter(lambda deck:deck.name == tp.tag_name,context.decks)))
    if not did:
        return status
    did = did[0]
    if tp.tag_name in card.get_note().tags and did == card.did:
        context._counter += 1
        if context._counter == context._number_of_card_with_tag:
            status.emit(EventMoveAllCards())
        else:
            status.emit(EventMoveCard())
            status.mark_progress()
    return status

def handle_done(context: Context,message) -> Status:
    status = Status()
    if not context.monitor.is_event_triggered(EventAddDeck()):
        status2 = handle_storage_add_deck(context,message)
        context.trigger_event_immediately(status2.metric)
        status.metric.extend(status2.metric)
        
    if not context.monitor.is_event_triggered(EventMoveAllCards()):
        context.update_database()
        cards : List[Card] = list(filter(lambda c:tp.tag_name in c.get_note().tags,AnkiObjMap().array_by_type("card")))
        if all([c.did == context._this_did for c in cards]):
            status.emit(EventMoveCard())
            status.emit(EventMoveAllCards())
    return status
        
TRACE_HANDLERS = {
    "storage_add_deck": handle_storage_add_deck,
    "storage_update_card": handle_storage_update_card,
}   
dependency_graph = {
    add_deck_: [],
    move_card_: [],
    move_all_cards_ : [move_card_]
}
finished_list = [
    move_all_cards_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list,done=handle_done)