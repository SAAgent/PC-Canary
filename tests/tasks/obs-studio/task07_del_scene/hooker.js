(function () {
    // 脚本设置
    const FUNCTION_NAME = "OBSBasic::Save";
    const FUNCTION_SYMBOL = "_ZN8OBSBasic4SaveEPKc";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_ON_SUCCESS = "scene_json_path";
    
    const MESSAGE_called = "拦截到函数调用";
    const MESSAGE_returned = "函数返回";
    const MESSAGE_ON_SUCCESS = "写入配置文件操作完成";
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
    function initHook_save() {
        const funcAddr = getFunctionAddress(FUNCTION_SYMBOL);
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
                this.file_path = args[1];
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL
                });
                const val = this.file_path.readCString(-1);
                sendEvent(EVENT_ON_SUCCESS, {
                    message: MESSAGE_ON_SUCCESS,
                    path: val,
                });
            }
        })
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        initHook_save();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})(); 