#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import datetime
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_clear_unused_tags(context: Context,message,data) -> Status:
    status = Status()
    status.emit(EventClearUnusedTags())
    return status

TRACE_HANDLERS = {
    "service_clear_unused_tags": handle_clear_unused_tags,
}   
dependency_graph = {
    clear_unused_tags_ : [],
}
finished_list = [
    clear_unused_tags_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)