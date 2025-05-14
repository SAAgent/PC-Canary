(function () {
    // Script settings
    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    
    const MESSAGE_source_deleted = "Source has been deleted";
    const MESSAGE_script_initialized = "Monitoring script has started";
    const MESSAGE_hook_installed = "Monitoring hook installed, waiting for operation...";

    // Send events to the evaluation system
    function sendEvent(eventType, data = {}) {
        console.log("[Event]", eventType, JSON.stringify(data, null, 2));
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    // Get function address
    function getFunctionAddress(functionName) {
        console.log("[Debug] Searching for function:", functionName);
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            console.log("[Error] Function not found:", functionName);
            sendEvent("error", {
                error_type: "function_not_found",
                message: `Unable to find function ${functionName}`
            });
            return null;
        }

        console.log("[Debug] Found function address:", functionName, funcAddr);
        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `Found actual address of function ${functionName}`
        });
        return funcAddr;
    }

    // Get source of scene item
    function obs_sceneitem_get_source(item) {
        const func = new NativeFunction(
            getFunctionAddress("obs_sceneitem_get_source"),
            'pointer',
            ['pointer']
        );
        return func(item);
    }

    // Monitor deletion of scene items
    function hookSceneItemRemove() {
        console.log("[Hook] Setting up hook for obs_sceneitem_remove");
        const funcAddr = getFunctionAddress("obs_sceneitem_remove");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.item = args[0];
                if (this.item) {
                    try {
                        const source = new OBSSource(obs_sceneitem_get_source(this.item));
                        const source_name = source.getName();
                        const source_id = source.getId();

                        console.log("[obs_sceneitem_remove] Source name:", source_name);
                        console.log("[obs_sceneitem_remove] Source type:", source_id);

                        // Only focus on color sources
                        if (source_id === "color_source_v3") {
                            sendEvent("source_deleted", {
                                source_name: source_name,
                                source_id: source_id,
                                message: MESSAGE_source_deleted
                            });
                        }
                    } catch (error) {
                        console.log("[Error] Failed to get source information:", error);
                    }
                }
            }
        });
    }

    function hookSourceRemove() {
        console.log("[Hook] Setting up hook for obs_source_remove");
        const funcAddr = getFunctionAddress("obs_source_remove");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source = args[0];
                if (this.source) {
                    try {
                        const source = new OBSSource(this.source);
                        const source_name = source.getName();
                        const source_id = source.getId();

                        console.log("[obs_source_remove] Source name:", source_name);
                        console.log("[obs_source_remove] Source type:", source_id);

                        // Only focus on color sources
                        if (source_id === "color_source_v3") {
                            sendEvent("source_deleted", {
                                source_name: source_name,
                                source_id: source_id,
                                message: MESSAGE_source_deleted
                            });
                        }
                    } catch (error) {
                        console.log("[Error] Failed to get source information:", error);
                    }
                }
            }
        });
    }

    // OBSSource class for operating OBS sources
    class OBSSource {
        constructor(ptr) {
            console.log("[OBSSource] Creating new instance, pointer:", ptr);
            this.ptr = ptr;
        }

        getName() {
            console.log("[OBSSource] Getting source name");
            const func = new NativeFunction(
                getFunctionAddress("obs_source_get_name"),
                'pointer',
                ['pointer']
            );
            const namePtr = func(this.ptr);
            const name = namePtr.readCString(-1);
            console.log("[OBSSource] Retrieved source name:", name);
            return name;
        }

        getId() {
            console.log("[OBSSource] Getting source ID");
            const func = new NativeFunction(
                getFunctionAddress("obs_source_get_id"),
                'pointer',
                ['pointer']
            );
            const idPtr = func(this.ptr);
            const id = idPtr.readCString(-1);
            console.log("[OBSSource] Retrieved source ID:", id);
            return id;
        }
    }

    // Initialize hooks
    function initHook() {
        console.log("[Init] Starting hook initialization");
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize hooks
        hookSceneItemRemove();
        hookSourceRemove();

        console.log("[Init] Hook initialization completed");
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    console.log("[Start] Script execution started");
    initHook();
    console.log("[Start] Script execution completed, waiting for events...");
})();