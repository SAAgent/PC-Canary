(function () {
    // Related symbols
    const FUNC_CREATE = "obs_source_create";
    const FUNC_REMOVE = "obs_source_remove";
    const FUNC_SET_ORDER = "obs_sceneitem_set_order";
    const FUNC_SAVE = "OBSBasic::Save";
    const FUNC_SAVE_SYMBOL = "_ZN8OBSBasic4SaveEPKc";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_ON_SUCCESS = "scene_json_path";
    const PAYLOAD_SUCCESS = "path";

    const MESSAGE_SCRIPT_INITIALIZED = "Monitoring script has started";
    const MESSAGE_HOOK_INSTALLED = "Monitoring hook installed, waiting for operation...";
    const MESSAGE_ON_SUCCESS = "Batch management of color sources operation completed";

    // Record operations
    let addCount = 0, removeCount = 0, reorderCount = 0;
    let lastScenePath = null;

    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    function getFunctionAddress(functionName) {
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: `Unable to find function ${functionName}`
            });
            return null;
        }
        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `Found actual address of function ${functionName}`
        });
        return funcAddr;
    }

    // Hook: Add color source
    function hookCreate() {
        const addr = getFunctionAddress(FUNC_CREATE);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                const name = args[1].readUtf8String();
                const type = args[0].readUtf8String();
                if (type === "color_source") {
                    addCount++;
                    sendEvent(EVENT_ON_ENTER, { function: FUNC_CREATE, name });
                }
            },
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, { function: FUNC_CREATE });
            }
        });
    }

    // Hook: Remove color source
    function hookRemove() {
        const addr = getFunctionAddress(FUNC_REMOVE);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                removeCount++;
                sendEvent(EVENT_ON_ENTER, { function: FUNC_REMOVE });
            },
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, { function: FUNC_REMOVE });
            }
        });
    }

    // Hook: Reorder scene items
    function hookSetOrder() {
        const addr = getFunctionAddress(FUNC_SET_ORDER);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                reorderCount++;
                sendEvent(EVENT_ON_ENTER, { function: FUNC_SET_ORDER });
            },
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, { function: FUNC_SET_ORDER });
            }
        });
    }

    // Hook: Save scene, get JSON path
    function hookSave() {
        const addr = getFunctionAddress(FUNC_SAVE_SYMBOL);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.file = args[1].readCString(-1);
                sendEvent(EVENT_ON_ENTER, { function: FUNC_SAVE });
            },
            onLeave(retval) {
                lastScenePath = this.file;
                sendEvent(EVENT_ON_LEAVE, { function: FUNC_SAVE });
                if (lastScenePath && lastScenePath.endsWith(".json")) {
                    sendEvent(EVENT_ON_SUCCESS, {
                        message: MESSAGE_ON_SUCCESS,
                        [PAYLOAD_SUCCESS]: lastScenePath
                    });
                }
            }
        });
    }

    function initHook() {
        sendEvent("script_initialized", { message: MESSAGE_SCRIPT_INITIALIZED });
        hookCreate();
        hookRemove();
        hookSetOrder();
        hookSave();
        sendEvent("hook_installed", { message: MESSAGE_HOOK_INSTALLED });
    }

    initHook();
})();