#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import re
sys.path.append(os.path.dirname(__file__))
from common import *

def remove_html_tags(text):
    return re.sub(r'<[^>]+>', '', text)

def handle_storage_add_card(context: Context,message) -> Status:
    context.update_database()
    latest_card : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest_card.get_note()
    status = Status()
    status.emit(EventCardAdded())
    if len(note.fields) == 2:
        note = note.fields
        if not remove_html_tags(note[0]) == 'three largest countries in the world':
            status.emit(EventCardFormatWrong(remove_html_tags(note.fields[0]),'three largest countries in the world'))
            # status.mark_error()
            return status
        if note[0] != 'three <b>largest</b> countries in the world':
            status.emit(EventCardFormatWrong(note.fields[0],'three <b>largest</b> countries in the world'))
            # status.mark_error()
            return status
        if note[1] != "<ol><li>Russia</li><li>Canada</li><li>China</li></ol>":
            status.emit(EventCardFormatWrong(note[1],"<ol><li>Russia</li><li>Canada</li><li>China</li></ol>"))
            # status.mark_error()
            return status
        status.emit(EventCardFormatCorrect())
    # else:
    #     status.mark_error()
    return status
TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card,
}   
dependency_graph = {
    card_added_ : [],
    card_format_correct_ : [card_added_]
}
finished_list = [
    card_format_correct_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)