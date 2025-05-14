// OBS recording output configuration and test monitoring hook script
// Used to monitor OBS recording output path and format configuration, as well as recording test operations

(function () {
    // Script settings
    const FUNCTION_ConfigureRecording = "_ZN12SimpleOutput18ConfigureRecordingEb";
    const FUNCTION_StartRecording = "_ZN12SimpleOutput14StartRecordingEv";
    const FUNCTION_StopRecording = "_ZN12SimpleOutput13StopRecordingEb";
    // const FUNCTION_OBSBasic_GetCurrentOutputPath = "_ZN8OBSBasic20GetCurrentOutputPathEv";
    const FUNCTION_OBSBasicSettings_SaveOutputSettings = "_ZN16OBSBasicSettings18SaveOutputSettingsEv";

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

    // Initialize configure recording output hook
    function initConfigureRecordingHook() {
        const configureRecordingFuncAddr = getFunctionAddress(FUNCTION_ConfigureRecording);
        if (!configureRecordingFuncAddr) {
            return;
        }

        Interceptor.attach(configureRecordingFuncAddr, {
            onEnter: function(args) {
                this.updateReplayBuffer = args[1].toInt32();
                sendEvent("configure_recording_called", {
                    message: "Intercepted configure recording output function call",
                    updateReplayBuffer: this.updateReplayBuffer
                });
            },

            onLeave: function(retval) {
                sendEvent("configure_recording_returned", {
                    message: "Configure recording output function returned",
                    result: retval.toInt32() !== 0
                });
            }
        });
    }

    // Initialize save output settings hook
    function initSaveOutputSettingsHook() {
        const saveOutputSettingsFuncAddr = getFunctionAddress(FUNCTION_OBSBasicSettings_SaveOutputSettings);
        if (!saveOutputSettingsFuncAddr) {
            return;
        }

        Interceptor.attach(saveOutputSettingsFuncAddr, {
            onEnter: function(args) {
                // Save this pointer for access in onLeave
                this.settingsThis = args[0];
                sendEvent("save_output_settings_called", {
                    message: "Intercepted save output settings function call"
                });
            },

            onLeave: function(retval) {
                sendEvent("save_output_settings_returned", {
                    message: "Save output settings function returned"
                });
                
                try {
                    // Get configuration file path based on user-provided memory offset information
                    // Offset from this to this.main is 40
                    const mainPtr = this.settingsThis.add(40).readPointer();
                    if (mainPtr.isNull()) {
                        sendEvent("error", {
                            error_type: "get_main_failed",
                            message: "Failed to get main pointer"
                        });
                        return;
                    }
                    
                    // Offset from this.main to this.main.basicConfig is 800
                    const basicConfigPtr = mainPtr.add(800).readPointer();
                    if (basicConfigPtr.isNull()) {
                        sendEvent("error", {
                            error_type: "get_basic_config_failed",
                            message: "Failed to get basicConfig pointer"
                        });
                        return;
                    }
                    
                    // this.main.basicConfig.config.file pointer and this.main.basicConfig pointer have the same address
                    // this.main.basicConfig.config.file pointer points to a string pointer
                    const configFilePtr = basicConfigPtr.readPointer();
                    if (configFilePtr.isNull()) {
                        sendEvent("error", {
                            error_type: "get_config_file_failed",
                            message: "Failed to get config.file pointer"
                        });
                        return;
                    }
                    
                    const configFilePath = configFilePtr.readCString();
                    if (!configFilePath) {
                        sendEvent("error", {
                            error_type: "read_config_file_path_failed",
                            message: "Failed to read configuration file path"
                        });
                        return;
                    }
                    
                    // Send configuration file path to handler.py for reading and checking file content
                    // This ensures the file is fully written before checking its content
                    sendEvent("config_file_found", {
                        message: "Found configuration file path",
                        path: configFilePath
                    });
                    
                } catch (e) {
                    sendEvent("error", {
                        error_type: "check_config_failed",
                        message: `Failed to check configuration file: ${e.message}`
                    });
                }
            }
        });
    }

    // Initialize start recording hook
    function initStartRecordingHook() {
        const startRecordingFuncAddr = getFunctionAddress(FUNCTION_StartRecording);
        if (!startRecordingFuncAddr) {
            return;
        }

        Interceptor.attach(startRecordingFuncAddr, {
            onEnter: function(args) {
                sendEvent("start_recording_called", {
                    message: "Intercepted start recording function call"
                });
            },

            onLeave: function(retval) {
                sendEvent("start_recording_returned", {
                    message: "Start recording function returned",
                    result: retval.toInt32() !== 0
                });
            }
        });
    }

    // Initialize stop recording hook
    function initStopRecordingHook() {
        const stopRecordingFuncAddr = getFunctionAddress(FUNCTION_StopRecording);
        if (!stopRecordingFuncAddr) {
            return;
        }

        Interceptor.attach(stopRecordingFuncAddr, {
            onEnter: function(args) {
                this.force = args[1].toInt32() !== 0;
                sendEvent("stop_recording_called", {
                    message: "Intercepted stop recording function call",
                    force: this.force
                });
            },

            onLeave: function(retval) {
                sendEvent("stop_recording_returned", {
                    message: "Stop recording function returned"
                });
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: "OBS recording output configuration and test monitoring script has started"
        });

        // Initialize hooks
        initConfigureRecordingHook();
        initSaveOutputSettingsHook();
        initStartRecordingHook();
        initStopRecordingHook();
        
        sendEvent("hook_installed", {
            message: "Recording output configuration and test monitoring hooks installed, waiting for operation..."
        });
    }

    // Start script
    initHook();
})();
