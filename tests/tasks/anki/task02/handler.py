#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_add_deck(context: Context,message,data) -> Status:
    context.update_database()
    deck : Deck = sorted(AnkiObjMap().array_by_type("deck"),key=lambda x: x.mtime,reverse=True)[0]
    status = Status(status=StatusType.PROGRESS)
    if deck.name == tp.deck_name:
        status.emit(EventCorrectDeck())
        status.mark_success()
    else:
        status.emit(EventWrongDeck(deck.name, tp.deck_name))
    return status

TRACE_HANDLERS = {
    "storage_add_deck": handle_storage_add_deck,
}   
bind_handlers(TRACE_HANDLERS)