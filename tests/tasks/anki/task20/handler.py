#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_deck(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    deck : Deck = sorted(AnkiObjMap().array_by_type("deck"),key=lambda x: x.mtime,reverse=True)[0]
    status = Status(status=StatusType.PROGRESS)
    if deck.name == tp.tag_name:
        cards :List[Card] = list(filter(lambda c:tp.tag_name in c.get_note().tags,AnkiObjMap().array_by_type("card")))
        print(cards)
        context._this_did = deck.did
        context._number_of_card_with_tag = len(cards)
        context._counter = 0
        status.emit(EventAddDeck())
    return status

def handle_storage_update_card(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    card : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    if tp.tag_name in card.get_note().tags and context._this_did == card.did:
        context._counter += 1
        if context._counter == context._number_of_card_with_tag:
            status.emit(EventMoveAllCards())
        else:
            status.emit(EventMoveCard())
            status.mark_progress()
    return status


TRACE_HANDLERS = {
    "storage_add_deck": handle_storage_add_deck,
    "storage_update_card": handle_storage_update_card,
}   
dependency_graph = {
    add_deck_: [],
    move_card_: [add_deck_],
    move_all_cards_ : [move_card_]
}
finished_list = [
    move_all_cards_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)