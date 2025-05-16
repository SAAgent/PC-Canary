#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *


def handle_storage_update_card(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    for cid in context._cards_to_check:
        card : Card = AnkiObjMap().get(Card.generate_hash(cid))
        if card.flags == 1:
            status.emit(EventAddRedFlag())
            context._cards_to_check.remove(cid)
            status.mark_progress()
            break
    if not context._cards_to_check:
        status.emit(EventAddAllRedFlags())
    return status

def scan_items(context: Context):
    context.update_database()
    cards : List[Card] = list(map(lambda c:c.cid,filter(lambda c: tp.tag_name in c.get_note().tags, AnkiObjMap().array_by_type("card"))))
    context._cards_to_check = cards
    assert len(cards) > 0, "No cards found with the tag"
    
def handle_done(context: Context,message):
    if not context.monitor.is_event_triggered(EventAddAllRedFlags()):
        return handle_storage_update_card(context,None)

TRACE_HANDLERS = {
    "storage_update_card": handle_storage_update_card,
}   
dependency_graph = {
    add_red_flag_ : [],
    add_all_red_flags_ : [add_red_flag_]
}
finished_list = [
    add_all_red_flags_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list,init=scan_items,done=handle_done)