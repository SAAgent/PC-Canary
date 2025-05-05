const TRACE_FUNCTION = [
   "service_remove_notes" 
]
function initHooks() {
    // iterate function name and addr, init it.
    for (const function_name of TRACE_FUNCTION){
        initHook(function_name, TRACE_MAPS[function_name]);
    }
}
initHooks();
sendLog("info", "add hooks done");