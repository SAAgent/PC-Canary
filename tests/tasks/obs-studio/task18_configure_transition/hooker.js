(function () {
    // Script settings
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
    function getFunctionAddress(functionName, symbolName) {
        console.log(`[Debug] Attempting to get address of function ${functionName} (symbol: ${symbolName})`);

        const funcAddr = DebugSymbol.getFunctionByName(symbolName);
        if (!funcAddr) {
            console.log(`[Error] Unable to find function ${functionName} (symbol: ${symbolName})`);
            return null;
        }

        console.log(`[Debug] Found actual address of function ${functionName} (symbol: ${symbolName}): ${funcAddr.toString()}`);
        return funcAddr;
    }

    // Initialize transition configuration hook
    function hookTransitionConfig() {
        // Monitor transition start function
        let startFunc = "obs_transition_start";
        let startSymbol = "obs_transition_start";

        const startAddr = getFunctionAddress(startFunc, startSymbol);
        if (startAddr) {
            Interceptor.attach(startAddr, {
                onEnter(args) {
                    this.transition = args[0];
                    this.duration = args[2].toInt32();
                    this.dest = args[3];
                    console.log(`[Debug] Transition start function called, duration: ${this.duration}ms`);
                },
                
                onLeave(retval) {
                    // Get transition name
                    const getSourceName = new NativeFunction(
                        DebugSymbol.getFunctionByName("obs_source_get_name"),
                        'pointer',
                        ['pointer']
                    );
                    const namePtr = getSourceName(this.transition);
                    const transitionName = namePtr.readCString();
                    const destName = getSourceName(this.dest).readCString();

                    console.log(`[Debug] Transition started: type=${transitionName}, duration=${this.duration}ms`);
                    
                    // Send transition configuration information
                    sendEvent("transition_executed", {
                        transition_name: transitionName,
                        duration_ms: this.duration,
                        success: retval.toInt32() !== 0,
                        dest: destName
                    });
                }
            });
        }
    }

    // Initialize hooks
    function initHook() {
        console.log("[Init] Starting hook initialization");
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize transition configuration hook
        hookTransitionConfig();
        
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