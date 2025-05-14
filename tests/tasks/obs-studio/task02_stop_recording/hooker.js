// OBS recording update monitoring hook script
// Used to monitor OBS recording update operations

(function () {
    // Script settings
    const FUNCTION_obs_output_stop = "obs_output_stop";
    const FUNCTION_obs_output_force_stop = "obs_output_force_stop";

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
    function initStopRecordingHook() {

        const obsOutputStopFuncAddr = getFunctionAddress(FUNCTION_obs_output_stop);
        if (!obsOutputStopFuncAddr) {
            return;
        }

        const obsOutputFroceStopFuncAddr = getFunctionAddress(FUNCTION_obs_output_force_stop);
        if (!obsOutputFroceStopFuncAddr) {
            return;
        }

        Interceptor.attach(obsOutputStopFuncAddr, {
            onEnter: function(args) {
                sendEvent("obs_output_stop_called", {
                    message: "Intercepted the function call to stop recording"
                });
            },

            onLeave: function(retval) {
                sendEvent("obs_output_stop_returned", {
                    message: "Stop recording function returned"
                });
            }
        });

        Interceptor.attach(obsOutputFroceStopFuncAddr, {
            onEnter: function(args) {
                sendEvent("obs_output_force_stop_called", {
                    message: "Intercepted the function call to force stop recording"
                });
            },

            onLeave: function(retval) {
                sendEvent("obs_output_force_stop_returned", {
                    message: "Force stop recording function returned"
                });
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: "OBS stop recording monitoring script has started"
        });

        // Initialize each hook
        initStopRecordingHook();
        sendEvent("hook_installed", {
            message: "Stop recording monitoring hook installed, waiting for operation..."
        });
    }

    // Start script
    initHook();
})();