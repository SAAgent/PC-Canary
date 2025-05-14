// OBS scene switching hook script
// Used to monitor OBS scene switching operations

(function () {
    // Script settings
    const FUNCTION_SetCurrentScene = "_ZN8OBSBasic15SetCurrentSceneE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEEb";

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
    function initSetCurrentSceneHook() {

        const SetCurrentSceneFuncAddr = getFunctionAddress(FUNCTION_SetCurrentScene);
        if (!SetCurrentSceneFuncAddr) {
            return;
        }

        Interceptor.attach(SetCurrentSceneFuncAddr, {
            onEnter: function(args) {
                sendEvent("setCurrentScene_called", {
                    message: "Intercepted the function call to switch the current scene"
                });
                const scene = new NativePointer(args[1]);
                console.log("scene pointer: ", scene);
                const scene_val = scene.readPointer();
                console.log("scene_val pointer: ", scene_val);
                const name_pointer = scene_val.readPointer();
                console.log("name pointer: ", name_pointer);
                const name = name_pointer.readCString(-1);
                console.log("name: ", name);
                this.name = name;
                this.force = args[2];
            },

            onLeave: function(retval) {
                sendEvent("setCurrentScene_returned", {
                    message: "Switch current scene function returned"
                });
                console.log("this.name: ", this.name);
                console.log("this.force: ", this.force);
                sendEvent("current_scene", {
                    scene: this.name,
                    message: `Current scene name: ${this.name}`
                })
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: "OBS scene switching monitoring script has started"
        });

        // Initialize each hook
        initSetCurrentSceneHook();
        sendEvent("hook_installed", {
            message: "Scene switching monitoring hook installed, waiting for operation..."
        });
    }

    // Start script
    initHook();
})();