#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_update_card(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    cards : List[Card] = list(filter(lambda card: tp.tag_name in card.get_note().tags,AnkiObjMap().array_by_type("card")))
    if all([card.queue == -3 for card in cards]):
        status.emit(EventDelay())
    return status 

TRACE_HANDLERS = {
    "storage_update_card": handle_storage_update_card,
}   
dependency_graph = {
    delay_: [],
}
finished_list = [
    delay_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)