//! The script only tested in x86-64!
const TRACE_FUNCTION = {
        "storage_add_card": {
            "addr": 0x00000000007065a0,
        }
}
function initHooks() {
    // iterate function name and addr, init it.
    for (const [function_name, config] of Object.entries(TRACE_FUNCTION)) {
        initHook(function_name, config);
    }
}
initHooks();
sendLog("info", "add hooks done");