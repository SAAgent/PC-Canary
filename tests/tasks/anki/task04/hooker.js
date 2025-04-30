//! The script only tested in x86-64!

const TRACE_FUNCTION = [
    "storage_add_deck",
    "storage_remove_deck",
    "service_undo"
]
function initHooks() {
    // iterate function name and addr, init it.
    for (const function_name of TRACE_FUNCTION){
        initHook(function_name, TRACE_MAPS[function_name]);
    }
}
initHooks();
sendLog("info", "add hooks done");