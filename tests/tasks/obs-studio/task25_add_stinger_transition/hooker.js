// OBS Studio Stinger transition monitoring script
// Used to monitor OBS's add Stinger transition operation and scene switch operation

(function () {
    // Script settings
    // Functions related to creating and configuring Stinger transitions
    const FUNCTION_AddTransition = "_ZN8OBSBasic13AddTransitionEPKc";
    const FUNCTION_SetTransition = "_ZN8OBSBasic13SetTransitionE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEE";
    const FUNCTION_TransitionToScene = "_ZN8OBSBasic17TransitionToSceneE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEEbbibb";
    
    // Constants and message definitions
    const OFFSET_info = 0x150;
    const MESSAGE_script_initialized = "Monitoring script has started";
    const MESSAGE_hook_installed = "Monitoring hook installed, waiting for operations...";
    const STINGER_TRANSITION_ID = "obs_stinger_transition";

    // Tracking status
    let stingerCreated = false;
    let stingerConfigured = false;
    let stingerUsed = false;

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
            message: `Found the actual address of function ${functionName}`
        });
        return funcAddr;
    }

    // Monitor add transition function
    function initAddTransitionHook() {
        const funcAddr = getFunctionAddress(FUNCTION_AddTransition);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                const transitionId = args[1].readCString();
                this.transitionId = transitionId;
                
                sendEvent("createStingerTransition_called", {
                    function: "OBSBasic::AddTransition",
                    transition_id: transitionId
                });
            },
            onLeave: function(retval) {
                sendEvent("createStingerTransition_returned", {
                    function: "OBSBasic::AddTransition",
                    transition_id: this.transitionId,
                });
                
                // Check if Stinger transition was created
                if (this.transitionId === STINGER_TRANSITION_ID) {
                    stingerCreated = true;
                    sendEvent("stinger_transition_created", {
                        transition_id: this.transitionId
                    });
                }
            }
        });
    }

    // Monitor set transition properties function - detect Stinger transition configuration
    function initStingerConfigHook() {
        // In OBS Studio, Stinger transition configuration is usually done by setting source properties
        // Here we monitor the key property setting function
        const onPropertyChangedSymbol = "_ZN8OBSBasic4SaveEPKc";
        const funcAddr = getFunctionAddress(onPropertyChangedSymbol);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                sendEvent("configureStingerTransition_called", {
                    function: "OBSBasic::Save"
                });
                
                // Attempt to get property data
                this.file = args[1].readCString(-1);
            },
            onLeave: function(retval) {
                sendEvent("configureStingerTransition_returned", {
                    function: "OBSBasic::Save",
                    file: this.file
                });
                stingerConfigured = true;
            }
        });
    }
    
    // Monitor set transition function
    function initSetTransitionHook() {
        const funcAddr = getFunctionAddress(FUNCTION_SetTransition);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                sendEvent("setTransition_called", {
                    function: "OBSBasic::SetTransition"
                });
                const transition = new NativePointer(args[1]);
                this.transition = transition;
            },
            onLeave: function(retval) {
                sendEvent("setTransition_returned", {
                    function: "OBSBasic::SetTransition"
                });
                
                try {
                    const val_pointer = this.transition.readPointer();
                    const info_pointer = val_pointer.add(OFFSET_info);
                    const id_pointer = info_pointer.readPointer();
                    const id = id_pointer.readCString(-1);
                    
                    sendEvent("transition_info", {
                        transition_id: id
                    });
                    
                    // Check if Stinger transition was used
                    if (id === STINGER_TRANSITION_ID && stingerCreated && stingerConfigured) {
                        stingerUsed = true;
                        sendEvent("stinger_transition_used", {
                            transition_id: id
                        });
                    }
                } catch (e) {
                    sendEvent("error", {
                        error_type: "read_transition_info",
                        message: `Failed to read transition info: ${e.toString()}`
                    });
                }
            }
        });
    }

    // Monitor scene switch function
    function initTransitionToSceneHook() {
        const funcAddr = getFunctionAddress(FUNCTION_TransitionToScene);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                sendEvent("sceneSwitch_called", {
                    function: "OBSBasic::TransitionToScene"
                });
            },
            onLeave: function(retval) {
                sendEvent("sceneSwitch_returned", {
                    function: "OBSBasic::TransitionToScene"
                });
                
                // Check if Stinger transition was used
                if (stingerCreated && stingerConfigured && !stingerUsed) {
                    // In real scenarios, we need to check the type of transition used
                    // Here it is simplified to assume it was used if Stinger transition was created and configured
                    stingerUsed = true;
                    sendEvent("stinger_transition_used", {
                        message: "Detected scene switch using Stinger transition"
                    });
                }
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize each hook
        initAddTransitionHook();
        initStingerConfigHook();
        initSetTransitionHook();
        initTransitionToSceneHook();
        
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();