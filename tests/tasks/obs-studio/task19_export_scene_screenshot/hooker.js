(function () {
    // Script settings
    const FUNCTION_MUXANDFINISH = "ScreenshotObj::MuxAndFinish";
    const FUNCTION_SCREENSHOT = "OBSBasic::Screenshot";
    const FUNCTION_GETOUTPUTFILENAME = "GetOutputFilename";
    const SYMBOL_MUXANDFINISH = "_ZN13ScreenshotObj12MuxAndFinishEv";
    const SYMBOL_SCREENSHOT = "_ZN8OBSBasic10ScreenshotE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEE";
    const SYMBOL_GETOUTPUTFILENAME = "_Z17GetOutputFilenameB5cxx11PKcS0_bbS0_";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_GET_PATH = "screenshot_getpath";
    const EVENT_ON_SUCCESS = "screenshot_saved";
    const EVENT_ON_ERROR = "screenshot_error";
    
    const MESSAGE_screenshot_called = "Intercepted screenshot function call";
    const MESSAGE_screenshot_returned = "Screenshot function returned";
    const MESSAGE_getfilename_called = "Intercepted get filename function call";
    const MESSAGE_getfilename_returned = "Get filename function returned";
    const MESSAGE_ON_SUCCESS = "Screenshot saved successfully";
    const MESSAGE_ON_ERROR = "Screenshot save failed";
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

    // Initialize screenshot hook
    function initHook_screenshot() {
        const funcAddr = getFunctionAddress(SYMBOL_SCREENSHOT);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                try {
                    sendEvent(EVENT_ON_ENTER, {
                        message: MESSAGE_screenshot_called,
                        function: FUNCTION_SCREENSHOT,
                        symbol: SYMBOL_SCREENSHOT
                    });
                    
                    // Save source parameter for later use
                    this.source = args[1];
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "Failed to retrieve screenshot function call parameters",
                        error: error.toString()
                    });
                }
            },
            
            onLeave(retval) {
                try {
                    sendEvent(EVENT_ON_LEAVE, {
                        message: MESSAGE_screenshot_returned,
                        function: FUNCTION_SCREENSHOT,
                        symbol: SYMBOL_SCREENSHOT,
                        success: retval.toInt32() !== 0
                    });
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "Failed to retrieve screenshot function return value",
                        error: error.toString()
                    });
                }
            }
        });
    }

    // Initialize get filename hook
    function initHook_getOutputFilename() {
        const funcAddr = getFunctionAddress(SYMBOL_GETOUTPUTFILENAME);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                console.log("call getoutputfilename");
                try {
                    sendEvent(EVENT_ON_ENTER, {
                        message: MESSAGE_getfilename_called,
                        function: FUNCTION_GETOUTPUTFILENAME,
                        symbol: SYMBOL_GETOUTPUTFILENAME
                    });
                    
                    // Save parameters for onLeave use
                    this.path = args[0].readCString();
                    this.container = args[1].readCString();
                    this.noSpace = args[2].toInt32();
                    this.overwrite = args[3].toInt32();
                    this.format = args[4].readCString();
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "Failed to retrieve get filename function parameters",
                        error: error.toString()
                    });
                }
            },
            
            onLeave(retval) {
                try {
                    // Retrieve returned file path
                    const filePath = retval.readPointer().readCString();
                    console.log(filePath);
                    
                    sendEvent(EVENT_ON_LEAVE, {
                        message: MESSAGE_getfilename_returned,
                        function: FUNCTION_GETOUTPUTFILENAME,
                        symbol: SYMBOL_GETOUTPUTFILENAME,
                        path: this.path,
                        container: this.container,
                        noSpace: this.noSpace,
                        overwrite: this.overwrite,
                        format: this.format,
                        filePath: filePath
                    });
                    
                    // Send screenshot save path event
                    sendEvent(EVENT_GET_PATH, {
                        message: "Obtained saved path",
                        save_path: filePath
                    });
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "Failed to retrieve get filename function return value",
                        error: error.toString()
                    });
                }
            }
        });
    }

    function initHook_muxAndFinish() {
        const funcAddr = getFunctionAddress(SYMBOL_MUXANDFINISH);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                console.log("call muxandfinish");
                try {
                    sendEvent(EVENT_ON_ENTER, {
                        message: "muxAndFinish called",
                        function: FUNCTION_MUXANDFINISH,
                        symbol: SYMBOL_MUXANDFINISH
                    });
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "muxAndFinish function call failed",
                        error: error.toString()
                    });
                }
            },
            onLeave(retval) {
                try {
                    sendEvent(EVENT_ON_LEAVE, {
                        message: "muxAndFinish exited",
                        function: FUNCTION_MUXANDFINISH,
                        symbol: SYMBOL_MUXANDFINISH
                    });
                    sendEvent(EVENT_ON_SUCCESS, {
                        message: MESSAGE_ON_SUCCESS
                    });
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "muxAndFinish function return handling failed",
                        error: error.toString()
                    });
                }
            }
        });
    }

    function initRequestHandlerSaveScreenshotHook() {
        const funcAddr = getFunctionAddress("_ZN14RequestHandler20SaveSourceScreenshotERK7Request");
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                console.log("call RequestHandler");
            },
            onLeave(retval) {
                console.log("leave RequestHandler");
                sendEvent("RequestHandlerSaveScreenshot_returned", {
                    message: MESSAGE_ON_SUCCESS
                });
            }
        });
    }

    // Initialize hooks
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize hooks
        initHook_screenshot();
        initHook_getOutputFilename();
        initHook_muxAndFinish();
        initRequestHandlerSaveScreenshotHook();
        
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    initHook();
})();