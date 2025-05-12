#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import re
sys.path.append(os.path.dirname(__file__))
from common import *

def remove_html_tags(text):
    return re.sub(r'<[^>]+>', '', text)

def check_fields(note) -> bool:
    if re.findall(r'Three\s+<b>\s*largest\s*</b>\s+countries\s+in\s+the\s+world', note,re.DOTALL):
        return True
    return False

def check_fields2(note) -> bool:
    if re.findall(r"<ol>\s*<li>\s*Russia\s*</li>\s*<li>\s*Canada\s*</li>\s*<li>\s*China\s*</li>\s*</ol>",note,re.DOTALL):
        return True
    return False

def handle_storage_add_card(context: Context,message) -> Status:
    context.update_database()
    latest_card : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest_card.get_note()
    status = Status()
    status.emit(EventCardAdded())
    if len(note.fields) == 2:
        note = note.fields
        if not check_fields(note[0]):
            status.emit(EventCardFormatWrong(note[0],'Three <b>largest</b> countries in the world'))
            # status.mark_error()
            return status
        if not check_fields2(note[1]):
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