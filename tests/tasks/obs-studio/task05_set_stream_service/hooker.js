(function () {
    // Script settings
    const FUNCTION_NAME = "OBSBasicSettings::SaveStream1Settings";
    const FUNCTION_SYMBOL = "_ZN16OBSBasicSettings19SaveStream1SettingsEv";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_ON_SUCCESS = "current_stream_service";

    const PAYLOAD_SUCCESS = "stream_service";
    
    const MESSAGE_called = "Intercepted function call";
    const MESSAGE_returned = "Function returned";
    const MESSAGE_ON_SUCCESS = "Successfully set the streaming service";
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
    function initHook_inner() {
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
                const this_ptr = new NativePointer(args[0]);
                this.this_ptr = this_ptr;
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL
                });
                const main_offset = 40;
                const this_ptr = this.this_ptr;
                const main_ptr = this_ptr.add(main_offset);
                const main = main_ptr.readPointer();
                const service_offset = 640;
                const service_pointer = main.add(service_offset);
                const val = service_pointer.readPointer();
                const settings_offset = 24;
                const settings_pointer = val.add(settings_offset);
                const settings = settings_pointer.readPointer();
                const obs_data_get_string = new NativeFunction(Module.findExportByName(null, "obs_data_get_string"), 'pointer', ['pointer', 'pointer']);
                const name_ptr = obs_data_get_string(settings, Memory.allocUtf8String('service'));
                const name = name_ptr.readCString(-1);
                sendEvent(EVENT_ON_SUCCESS, {
                    message: MESSAGE_ON_SUCCESS,
                    [PAYLOAD_SUCCESS]: name
                });
            }
        })
    }

    function inithook_savejsonsafe() {
        const funcAddr = getFunctionAddress("obs_data_save_json_safe");
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
                this.json = args[1].readCString();
                console.log(this.json);
            },
            
            onLeave(retval) {
                console.log(retval);
                sendEvent("obs_data_save_json_safe_returned", {
                    message: MESSAGE_returned,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL,
                    json: this.json,
                    success: retval
                });
            }
        })
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize individual hooks
        initHook_inner();
        inithook_savejsonsafe();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();