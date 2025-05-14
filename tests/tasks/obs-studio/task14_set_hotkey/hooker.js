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
        let function_name = "create_binding";
        let symbol_name = "create_binding";

        Interceptor.attach(getFunctionAddress(function_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
                const name = args[0].add(8).readPointer().readCString(-1);
                this.name = name;
                console.log(name);
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name
                });
                sendEvent("set_hotkey_success", {
                    message: "Create new hotkey completed",
                    name: this.name
                });
            }
        });
    }

    function hook_obs_save_hotkey() {
        const function_name = "OBSBasicSettings::SaveSettings";
        const symbol_name = "_ZN16OBSBasicSettings12SaveSettingsEv";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
                const main_offset = 0x28;
                const main = args[0].add(main_offset).readPointer();
                const getConfigAddr = getFunctionAddress("_ZNK8OBSBasic6ConfigEv");
                const getConfig = new NativeFunction(getConfigAddr, 'pointer', ['pointer']);
                const config_ptr = getConfig(main);
                const file_name = config_ptr.readPointer().readCString(-1);
                this.file = file_name;
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name
                });
                sendEvent("save_success", {
                    message: "Configuration file saved",
                    file: this.file
                });
            }
        });
    }

    function hook_obs_hotkey_press() {
        const function_name = "obs_hotkey_pair_first_func";
        const symbol_name = "obs_hotkey_pair_first_func";
        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
                const name_offset = 0x8;
                const name = args[2].add(name_offset).readPointer().readCString(-1);
                this.name = name;
                this.pressed = args[3];
            },

            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name
                });
                console.log(this.pressed);
                sendEvent("hotkey_press", {
                    message: "Hotkey triggered",
                    name: this.name,
                    pressed: this.pressed == 0x1 ? "true" : "false"
                });
            }
        });
    }

    function init_hotkey_inject() {
        Interceptor.attach(getFunctionAddress("inject_hotkey"), {
            onEnter(args) {
                this.binding = args[2];
            },
            onLeave(retval) {
                const obs_hotkey_binding_get_hotkey = new NativeFunction(
                    getFunctionAddress("obs_hotkey_binding_get_hotkey"),
                    'pointer', ['pointer']
                );
                const obs_hotkey_get_name = new NativeFunction(
                    getFunctionAddress("obs_hotkey_get_name"),
                    'pointer', ['pointer']
                );
                const hotkey = obs_hotkey_binding_get_hotkey(this.binding);
                const name = obs_hotkey_get_name(hotkey).readCString();
                console.log(name);
                const pressed = this.binding.add(8).readU8();
                console.log(pressed);
                sendEvent("inject_hotkey", {
                    message: "Hotkey triggered",
                    name: name,
                    pressed: pressed == 0x1 ? "true" : "false"
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
        hook_obs_save_hotkey();
        hook_obs_hotkey_press();
        init_hotkey_inject();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();