(function () {
    // 脚本设置
    const FUNCTION_NAME = "obs_source_create";
    const FUNCTION_SYMBOL = "obs_source_create";
    const FUNCTION = "obs_data_get_bool";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_SUCCESS = "create_success";
    
    const MESSAGE_called = "拦截到函数调用";
    const MESSAGE_returned = "函数返回";
    const MESSAGE_ON_SUCCESS = "创建新的源操作完成";
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

    // 初始化录制更新钩子
    function hook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL
                });
                this.name = args[1].readCString(-1);
                this.type = args[0].readCString(-1);
                console.log(this.name);
                console.log(this.type);
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL
                });
                sendEvent(EVENT_SUCCESS, {
                    message: MESSAGE_ON_SUCCESS,
                    name: this.name,
                    type: this.type
                });
            }
        });

        
        Interceptor.attach(getFunctionAddress(FUNCTION), {
            onEnter(args) {
                this.name = args[1].readCString(-1);
                if (this.name != "looping") {
                    return;
                }
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: FUNCTION,
                    symbol: FUNCTION
                });
            },
            
            onLeave(retval) {
                if (this.name != "looping") {
                    return;
                }
                console.log(retval);
                if (this.name == "looping") {
                    sendEvent(EVENT_ON_LEAVE, {
                        message: MESSAGE_returned,
                        function: FUNCTION,
                        symbol: FUNCTION
                    });
                    sendEvent("updated_source", {
                        message: "更新源完成",
                        looping: retval == 1 ? "true" : "false"
                    });
                }
            }
        });

        Interceptor.attach(getFunctionAddress("obs_scene_create"), {
            onEnter(args) {
                this.name = args[0].readCString(-1);
                console.log(this.name);
            },

            onLeave(retval) {
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        hook();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})(); 