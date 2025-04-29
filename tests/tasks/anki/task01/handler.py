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
        status.emit(EventCorrectField())
        deck = latest.get_deck()
        if deck.name == "系统默认":
            status.emit(EventCorrectDeck())
            status.mark_success()
        else:
            status.emit(EventWrongDeck("系统默认",deck.name))
    else:
        status.emit(EventWrongField(note.fields,f"[{tp.first_field} {tp.second_field}]"))
    return status
      
def register_handlers(evaluator):
    config = evaluator.config
    if not "sql_path" in config:
        raise RuntimeError("Missing database file path")
    
    CONTEXT = Context(evaluator)
    
    CONTEXT.register_trace_handlers({
        "storage_add_card": handle_storage_add_card
    })
    message_handler.context = CONTEXT
    return message_handler

