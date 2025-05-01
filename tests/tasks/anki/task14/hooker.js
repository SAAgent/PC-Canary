const TRACE_FUNCTION = [
    "storage_add_card",
    "service_serach_cards",
    "service_find_and_replace",
]
function initHooks() {
    // iterate function name and addr, init it.
    for (const function_name of TRACE_FUNCTION){
        initHook(function_name, TRACE_MAPS[function_name]);
    }
}
initHooks();
sendLog("info", "add hooks done");