(function () {
    // Script settings
    const FUNCTION_NAME = "OBSBasic::Save";
    const FUNCTION_SYMBOL = "_ZN8OBSBasic4SaveEPKc";
    const FUNCTION_ADD_ITEM_NAME = "OBSBasic::AddSceneItem";
    const FUNCTION_ADD_ITEM_SYMBOL = "_ZN8OBSBasic12AddSceneItemE6OBSRefIP14obs_scene_itemXadL_Z20obs_sceneitem_addrefEEXadL_Z21obs_sceneitem_releaseEEE";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_ON_SUCCESS = "scene_json_path";
    const EVENT_ADD_ITEM_SUCCESS = "add_item_success";

    const MESSAGE_called = "Intercepted function call";
    const MESSAGE_returned = "Function returned";
    const MESSAGE_ON_SUCCESS = "Configuration file write operation completed";
    const MESSAGE_ADD_ITEM_ON_SUCCESS = "Add input source operation completed";
    const MESSAGE_script_initialized = "Monitoring script has started";
    const MESSAGE_hook_installed = "Monitoring hook installed, waiting for operation...";

    // Send events to the evaluation system
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    // Get function address
    function getFunctionAddress(functionName) {
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: `Cannot find function ${functionName}`
            });
            return null;
        }

        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `Found the actual address of function ${functionName}`
        });
        return funcAddr;
    }

    // Initialize recording update hooks
    function initHook_save() {
        const funcAddr = getFunctionAddress(FUNCTION_SYMBOL);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL
                });
                this.file_path = args[1];
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL
                });
                const val = this.file_path.readCString(-1);
                sendEvent(EVENT_ON_SUCCESS, {
                    message: MESSAGE_ON_SUCCESS,
                    path: val,
                });
            }
        });
    }

    function initHook_add_item() {
        const funcAddr = getFunctionAddress(FUNCTION_ADD_ITEM_SYMBOL);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: FUNCTION_ADD_ITEM_NAME,
                    symbol: FUNCTION_ADD_ITEM_SYMBOL
                });
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_ADD_ITEM_NAME,
                    symbol: FUNCTION_ADD_ITEM_SYMBOL
                });
                sendEvent(EVENT_ADD_ITEM_SUCCESS, {
                    message: MESSAGE_ADD_ITEM_ON_SUCCESS,
                });
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize individual hooks
        initHook_save();
        initHook_add_item();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();