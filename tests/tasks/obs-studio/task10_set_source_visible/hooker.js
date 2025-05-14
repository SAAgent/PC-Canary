(function () {
    // Script settings
    const FUNCTION_SET_VISIBLE_NAME = "obs_sceneitem_set_visible";
    const FUNCTION_SET_VISIBLE_SYMBOL = "obs_sceneitem_set_visible";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_SET_VISIBLE_SUCCESS = "set_visible_success";

    const MESSAGE_called = "Intercepted function call";
    const MESSAGE_returned = "Function returned";
    const MESSAGE_ON_SUCCESS = "Modify source visibility operation completed";
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
    function initHook_set_visible() {
        const funcAddr = getFunctionAddress(FUNCTION_SET_VISIBLE_NAME);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: FUNCTION_SET_VISIBLE_NAME,
                    symbol: FUNCTION_SET_VISIBLE_SYMBOL
                });
                this.visible = args[1].toInt32();
                const item_pointer = new NativePointer(args[0]);
                console.log(item_pointer);
                this.source_name = item_pointer.add(32).readPointer().readPointer().readCString(-1);
                console.log(this.source_name);
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_SET_VISIBLE_NAME,
                    symbol: FUNCTION_SET_VISIBLE_SYMBOL
                });
                sendEvent(EVENT_SET_VISIBLE_SUCCESS, {
                    message: MESSAGE_ON_SUCCESS,
                    flag: retval.toInt32(),
                    visible: this.visible,
                    source_name: this.source_name,
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
        initHook_set_visible();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();