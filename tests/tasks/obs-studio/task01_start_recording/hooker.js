// OBS Recording Update Monitor Hook Script
// Used to monitor OBS recording update operations

(function () {
    // Script settings
    const FUNCTION_NAME_StartRecording = "_ZN12SimpleOutput14StartRecordingEv";

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

    // Initialize recording update hook
    function initStartRecordingHook() {
        const startRecrodingFuncAddr = getFunctionAddress(FUNCTION_NAME_StartRecording);
        if (!startRecrodingFuncAddr) {
            return;
        }

        Interceptor.attach(startRecrodingFuncAddr, {
            onEnter: function(args) {
                sendEvent("start_recording_called", {
                    message: "Intercepted call to recording update function"
                });
            },

            onLeave: function(retval) {
                sendEvent("start_recording_returned", {
                    message: "Recording update function returned"
                });
                
                sendEvent("is_recording_active", {
                    recording: retval,
                    message: `Current recording status: ${retval}`
                });
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: "OBS recording update monitoring script started"
        });

        // Initialize individual hooks
        initStartRecordingHook();
        sendEvent("hook_installed", {
            message: "Recording update monitoring hook installed, waiting for operations..."
        });
    }

    // Start script
    initHook();
})();