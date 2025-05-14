(function () {
    // Script settings
    const MESSAGE_script_initialized = "Monitoring script has started";
    const MESSAGE_hook_installed = "Monitoring hook installed, waiting for operations...";
    const MESSAGE_config_updated = "Configuration update detected";

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

        sendEvent("debug", {
            address: funcAddr.toString(),
            message: `Found the actual address of function ${functionName}`
        });
        return funcAddr;
    }

    // Monitor configuration file modifications
    function hookConfigSave() {
        let function_name = "config_save";
        let symbol_name = "config_save";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                this.configFile = args[0];
                sendEvent("debug", {
                    message: "Saving configuration file",
                    function: function_name
                });
            },
            onLeave(retval) {
                sendEvent("config_saved", {
                    message: MESSAGE_config_updated,
                    function: function_name,
                    result: retval.toInt32(),
                    configFile: this.configFile.readPointer().readCString()
                });
            }
        });
    }

    // Monitor video bitrate settings
    function hookVideoBitrateSet() {
        let function_name = "config_set_int";
        let symbol_name = "config_set_int";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                if (args[0] === null) return;

                this.section = args[1].readCString();
                this.name = args[2].readCString();
                this.value = args[3].toInt32();

                // Check if setting video bitrate
                if (this.section === "SimpleOutput" && this.name === "VBitrate" && this.value === 2000) {
                    sendEvent("video_bitrate_set", {
                        message: "Video bitrate has been set to 2000",
                        section: this.section,
                        name: this.name,
                        value: this.value
                    });
                }

                // Check if setting replay time
                if (this.section === "SimpleOutput" && this.name === "RecRBTime" && this.value === 30) {
                    sendEvent("replay_time_set", {
                        message: "Maximum replay time has been set to 30 seconds",
                        section: this.section,
                        name: this.name,
                        value: this.value
                    });
                }
            },
            onLeave(retval) {}
        });
    }

    // Monitor encoder preset settings
    function hookEncoderPresetSet() {
        let function_name = "config_set_string";
        let symbol_name = "config_set_string";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                if (args[0] === null) return;

                this.section = args[1].readCString();
                this.name = args[2].readCString();
                
                // Check if string value is null
                if (args[3] !== null) {
                    this.value = args[3].readCString();
                    console.log("Set value:", this.value);
                
                    // Check if setting encoder preset
                    if (this.section === "SimpleOutput" && this.name === "Preset" && this.value === "faster") {
                        sendEvent("encoder_preset_set", {
                            message: "Encoder preset has been set to faster",
                            section: this.section,
                            name: this.name,
                            value: this.value
                        });
                    }

                    // Check if setting audio bitrate
                    if (this.section === "SimpleOutput" && this.name === "ABitrate" && this.value === "320") {
                        sendEvent("audio_bitrate_set", {
                            message: "Audio bitrate has been set to 320",
                            section: this.section,
                            name: this.name,
                            value: this.value
                        });
                    }
                }
            },
            onLeave(retval) {}
        });
    }

    // Monitor replay buffer enable settings
    function hookReplayBufferEnable() {
        let function_name = "config_set_bool";
        let symbol_name = "config_set_bool";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                if (args[0] === null) return;

                this.section = args[1].readCString();
                this.name = args[2].readCString();
                this.value = args[3].toInt32();

                // Check if enabling replay buffer
                if (this.section === "SimpleOutput" && this.name === "RecRB" && this.value === 1) {
                    sendEvent("replay_buffer_enabled", {
                        message: "Replay buffer has been enabled",
                        section: this.section,
                        name: this.name,
                        value: this.value
                    });
                }
            },
            onLeave(retval) {}
        });
    }

    // Initialize all hook functions
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize each hook
        hookConfigSave();
        hookVideoBitrateSet();
        hookEncoderPresetSet();
        hookReplayBufferEnable();

        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();