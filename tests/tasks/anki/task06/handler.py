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
    if len(note.fields) != 2:
        return status

    first_field = 'To <span style="color: rgb(255, 0, 0);">be</span> or <span style="color: rgb(255, 0, 0);">not to be</span>'
    second_field = "that's a question"

    if note.fields[0] == first_field and note.fields[1] == second_field:
        status.emit(EventCorrectField())
        status.emit(EventCorrectFormat())
    elif second_field == note.fields[1] and "To" in note.fields[0] and "be" in note.fields[0] and "not to be" in note.fields[0]:
        status.emit(EventCorrectField())
        status.emit(EventWrongFormat(f"{note.fields[0]}",first_field))
    else:
        status.emit(EventWrongField(note.fields,f"[{first_field} {second_field}]"))
    return status
      
TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card
}   
dependency_graph = {
    card_added_ : [],
    correct_field_ : [card_added_],
    wrong_field_ : [card_added_],
    correct_format_ : [card_added_],
    wrong_format_ : [card_added_]
}
finished_list = [
    correct_field_,correct_format_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)