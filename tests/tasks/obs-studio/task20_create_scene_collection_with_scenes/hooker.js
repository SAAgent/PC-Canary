(function () {
    // Script settings
    const FUNCTION_NAME_SAVE = "OBSBasic::Save";
    const FUNCTION_SYMBOL_SAVE = "_ZN8OBSBasic4SaveEPKc";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";

    const MESSAGE_CALLED = "Intercepted function call";
    const MESSAGE_RETURNED = "Function returned";
    const MESSAGE_SCRIPT_INITIALIZED = "Monitoring script has started";
    const MESSAGE_HOOK_INSTALLED = "Monitoring hook installed, waiting for operation...";

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

    // Initialize hook - Monitor OBSBasic::Save to get scene collection configuration file path
    function hookSaveSceneCollection() {
        const funcAddr = getFunctionAddress(FUNCTION_SYMBOL_SAVE);
        if (!funcAddr) {
            return;
        }

        // Monitor OBSBasic::Save function
        Interceptor.attach(funcAddr, {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_CALLED,
                    function: FUNCTION_NAME_SAVE,
                    symbol: FUNCTION_SYMBOL_SAVE
                });
                this.path = args[1].readCString();
                console.log("this.path is: ", this.path);
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_RETURNED,
                    function: FUNCTION_NAME_SAVE,
                    symbol: FUNCTION_SYMBOL_SAVE,
                    path: this.path,
                });
            }
        });
    }

    // Initialize hook
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_SCRIPT_INITIALIZED
        });

        // Initialize hooks
        hookSaveSceneCollection();

        sendEvent("hook_installed", {
            message: MESSAGE_HOOK_INSTALLED
        });
    }

    // Start script
    initHook();
})();