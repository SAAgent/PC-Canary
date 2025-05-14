// OBS scene switching hook script
// Used to monitor OBS scene switching operations

(function () {
    // Script settings
    const FUNCTION_SetTransition = "_ZN8OBSBasic13SetTransitionE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEE";
    const OFFSET_info = 0x150;
    const MESSAGE_called = "Intercepted function call";
    const MESSAGE_returned = "Function returned";
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
    function initSetTransitionHook() {

        const SetTransitionFuncAddr = getFunctionAddress(FUNCTION_SetTransition);
        if (!SetTransitionFuncAddr) {
            return;
        }

        Interceptor.attach(SetTransitionFuncAddr, {
            onEnter: function(args) {
                sendEvent("setTransition_called", {
                    message: MESSAGE_called,
                    function: "OBSBasic::SetTransition"
                });
                const transition = new NativePointer(args[1]);
                this.transition = transition;
            },

            onLeave: function(retval) {
                sendEvent("setTransition_returned", {
                    message: MESSAGE_returned,
                    function: "OBSBasic::SetTransition"
                });
                const val_pointer = this.transition.readPointer();
                console.log(val_pointer);
                const info_pointer = val_pointer.add(OFFSET_info);
                console.log(info_pointer);
                const id_pointer = info_pointer.readPointer();
                console.log(id_pointer);
                const id = id_pointer.readCString(-1);
                console.log('transition id: ', id);
                sendEvent("current_transition", {
                    transition: id,
                    message: `Current transition animation name: ${id}`
                })
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize each hook
        initSetTransitionHook();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();