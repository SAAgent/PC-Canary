#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import json
sys.path.append(os.path.dirname(__file__))
from common import *

def handle_storage_set_config(context: Context,message) -> Status:
    context.update_database()
    status = Status()
    config = context.anki_config["rollover"]
    if config == int(tp.time):
        status.emit(EventSetSucess())
    else:
        status.emit(EventSetWrong(str(config),tp.time))
    return status 

TRACE_HANDLERS = {
    "storage_set_config": handle_storage_set_config
}   
dependency_graph = {
    set_sucess_: [],
    set_wrong_ : []
}
finished_list = [
    set_sucess_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)