(function () {
    // Script settings
    const MESSAGE_script_initialized = "Monitoring script has started";
    const MESSAGE_hook_installed = "Monitoring hook installed, waiting for operation...";
    const MESSAGE_filter_created = "Captured filter creation event";
    const MESSAGE_filter_enabled = "Captured filter enabled event";
    const MESSAGE_filter_disabled = "Captured filter disabled event";
    const MESSAGE_filter_removed = "Captured filter removal event";

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

    // Create hook function
    function hookFilterCreate() {
        // Function: obs_source_filter_add, used to add filters
        let symbol_name = "obs_source_filter_add";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                this.source = args[0];
                this.filter = args[1];
                
                // Get source and filter names
                if (this.source && this.filter) {
                    try {
                        // Call obs_source_get_name to get source name
                        const obs_source_get_name = DebugSymbol.getFunctionByName("obs_source_get_name");
                        const sourceName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.source).readUtf8String();
                        const filterName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.filter).readUtf8String();
                        
                        // Call obs_source_get_unversioned_id to get filter type
                        const obs_source_get_id = DebugSymbol.getFunctionByName("obs_source_get_unversioned_id");
                        const filterId = new NativeFunction(obs_source_get_id, "pointer", ["pointer"])(this.filter).readUtf8String();

                        sendEvent("filter_created", {
                            message: MESSAGE_filter_created,
                            sourceName: sourceName,
                            filterName: filterName,
                            filterKind: filterId
                        });
                    } catch (e) {
                        sendEvent("error", {
                            error_type: "get_source_info_error",
                            message: `Error occurred while getting source information: ${e.toString()}`
                        });
                    }
                }
            }
        });
    }

    // Hook: Enable/Disable filter
    function hookFilterEnable() {
        // Function: obs_source_set_enabled, used to enable or disable filters
        let symbol_name = "obs_source_set_enabled";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                this.source = args[0];
                this.enabled = args[1].toInt32(); // Boolean parameter, 1 for enable, 0 for disable
                
                // Check if it is a filter
                if (this.source) {
                    try {
                        // Check if it is a filter
                        const obs_source_get_type = DebugSymbol.getFunctionByName("obs_source_get_type");
                        const sourceType = new NativeFunction(obs_source_get_type, "int", ["pointer"])(this.source);
                        
                        // OBS_SOURCE_TYPE_FILTER = 1
                        if (sourceType === 1) {
                            // Get filter name
                            const obs_source_get_name = DebugSymbol.getFunctionByName("obs_source_get_name");
                            const filterName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.source).readUtf8String();
                            
                            // Get parent source
                            const obs_filter_get_parent = DebugSymbol.getFunctionByName("obs_filter_get_parent");
                            const parent = new NativeFunction(obs_filter_get_parent, "pointer", ["pointer"])(this.source);
                            
                            let sourceName = "unknown";
                            if (parent) {
                                sourceName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(parent).readUtf8String();
                            }
                            
                            if (this.enabled === 1) {
                                sendEvent("filter_enabled", {
                                    message: MESSAGE_filter_enabled,
                                    sourceName: sourceName,
                                    filterName: filterName
                                });
                            } else {
                                sendEvent("filter_disabled", {
                                    message: MESSAGE_filter_disabled,
                                    sourceName: sourceName,
                                    filterName: filterName
                                });
                            }
                        }
                    } catch (e) {
                        sendEvent("error", {
                            error_type: "get_filter_enable_info_error",
                            message: `Error occurred while getting filter enable information: ${e.toString()}`
                        });
                    }
                }
            }
        });
    }

    // Hook: Remove filter
    function hookFilterRemove() {
        // Function: obs_source_filter_remove, used to remove filters
        let symbol_name = "obs_source_filter_remove";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                this.source = args[0];
                this.filter = args[1];
                
                // Get source and filter names
                if (this.source && this.filter) {
                    try {
                        // Call obs_source_get_name to get source name
                        const obs_source_get_name = DebugSymbol.getFunctionByName("obs_source_get_name");
                        const sourceName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.source).readUtf8String();
                        const filterName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.filter).readUtf8String();

                        sendEvent("filter_removed", {
                            message: MESSAGE_filter_removed,
                            sourceName: sourceName,
                            filterName: filterName
                        });
                    } catch (e) {
                        sendEvent("error", {
                            error_type: "get_source_info_error",
                            message: `Error occurred while getting source information: ${e.toString()}`
                        });
                    }
                }
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize hooks
        hookFilterCreate();
        hookFilterEnable(); 
        hookFilterRemove();

        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();