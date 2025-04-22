(function () {
    // 脚本设置
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
    
    const MESSAGE_screenshot_called = "拦截到截图函数调用";
    const MESSAGE_screenshot_returned = "截图函数返回";
    const MESSAGE_getfilename_called = "拦截到获取文件名函数调用";
    const MESSAGE_getfilename_returned = "获取文件名函数返回";
    const MESSAGE_ON_SUCCESS = "截图保存成功";
    const MESSAGE_ON_ERROR = "截图保存失败";
    const MESSAGE_script_initialized = "监控脚本已启动";
    const MESSAGE_hook_installed = "监控钩子安装完成，等待操作...";

    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    // 获取函数地址
    function getFunctionAddress(functionName) {
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: `无法找到函数 ${functionName}`
            });
            return null;
        }

        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `找到函数 ${functionName} 的实际地址`
        });
        return funcAddr;
    }

    // 初始化截图钩子
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
                    
                    // 保存source参数供后续使用
                    this.source = args[1];
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "截图函数调用参数获取失败",
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
                        message: "截图函数返回值获取失败",
                        error: error.toString()
                    });
                }
            }
        });
    }

    // 初始化获取文件名钩子
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
                    
                    // 保存参数供onLeave使用
                    this.path = args[0].readCString();
                    this.container = args[1].readCString();
                    this.noSpace = args[2].toInt32();
                    this.overwrite = args[3].toInt32();
                    this.format = args[4].readCString();
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "获取文件名函数参数获取失败",
                        error: error.toString()
                    });
                }
            },
            
            onLeave(retval) {
                try {
                    // 获取返回的文件路径
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
                    
                    // 发送截图保存路径事件
                    sendEvent(EVENT_GET_PATH, {
                        message: "获得了保存的路径",
                        save_path: filePath
                    });
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "获取文件名函数返回值获取失败",
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
                        message: "muxAndFinish 调用",
                        function: FUNCTION_MUXANDFINISH,
                        symbol: SYMBOL_MUXANDFINISH
                    });
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "muxAndFinish 函数调用失败",
                        error: error.toString()
                    });
                }
            },
            onLeave(retval) {
                try {
                    sendEvent(EVENT_ON_LEAVE, {
                        message: "muxAndFinish 退出",
                        function: FUNCTION_MUXANDFINISH,
                        symbol: SYMBOL_MUXANDFINISH
                    });
                    sendEvent(EVENT_ON_SUCCESS, {
                        message: MESSAGE_ON_SUCCESS
                    });
                } catch (error) {
                    sendEvent(EVENT_ON_ERROR, {
                        message: "muxAndFinish 函数返回处理失败",
                        error: error.toString()
                    });
                }
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        initHook_screenshot();
        initHook_getOutputFilename();
        initHook_muxAndFinish();
        
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})(); 