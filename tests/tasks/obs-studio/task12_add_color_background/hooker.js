(function () {
    // Script settings
    const FUNCTION_NAME = "obs_source_create";
    const FUNCTION_SYMBOL = "obs_source_create";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_SUCCESS = "create_success";

    const MESSAGE_called = "Intercepted function call";
    const MESSAGE_returned = "Function returned";
    const MESSAGE_ON_SUCCESS = "Create new source operation completed";
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
    function hook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME);
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
                this.name = args[1].readCString(-1);
                this.type = args[0].readCString(-1);
                console.log(this.name);
                console.log(this.type);
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL
                });
                sendEvent(EVENT_SUCCESS, {
                    message: MESSAGE_ON_SUCCESS,
                    name: this.name,
                    type: this.type
                });
            }
        });

        Interceptor.attach(getFunctionAddress("_ZN8OBSBasic4SaveEPKc"), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: "OBSBasic::Save",
                    symbol: "_ZN8OBSBasic4SaveEPKc"
                });
                this.path = args[1].readCString(-1);
                console.log(this.path);
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: "OBSBasic::Save",
                    symbol: "_ZN8OBSBasic4SaveEPKc"
                });
                sendEvent("config_save", {
                    message: "Configuration file saved",
                    path: this.path
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
        hook();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();