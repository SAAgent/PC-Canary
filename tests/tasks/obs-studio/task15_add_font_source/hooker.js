(function () {
    // 脚本设置
    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    
    const MESSAGE_called = "拦截到函数调用";
    const MESSAGE_returned = "函数返回";
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
        let function_name = "OBSBasic::Save";
        let symbol_name = "_ZN8OBSBasic4SaveEPKc";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
                this.file = args[1].readCString(-1);
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name,
                    file: this.file
                });
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