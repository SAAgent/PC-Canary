(function () {
    // Script settings
    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";

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
    function hook() {
        let function_name = "OBSBasic::on_actionImportProfile_triggered";
        let symbol_name = "_ZN8OBSBasic32on_actionImportProfile_triggeredEv";
        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name
                });
                sendEvent("import_success", {
                    message: "Profile import completed",
                    import_success: "True"
                });
            }
        });

        function_name = "OBSBasic::on_actionExportProfile_triggered";
        symbol_name = "_ZN8OBSBasic32on_actionExportProfile_triggeredEv";
        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name
                });
                sendEvent("export_success", {
                    message: "Profile export completed",
                });
            }
        });
    }

    function init_getconfig() {
        Interceptor.attach(getFunctionAddress("os_get_config_path"), {
            onEnter(args){
                this.name = args[0];
            },
            onLeave(retval) {
                sendEvent("get_config_path", {
                    message: "Get configuration file path",
                    path: this.name.readCString()
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
        init_getconfig();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();