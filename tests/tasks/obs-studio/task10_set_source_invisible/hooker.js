(function () {
    // 脚本设置
    const FUNCTION_SET_VISIBLE_NAME = "obs_sceneitem_set_visible";
    const FUNCTION_SET_VISIBLE_SYMBOL = "obs_sceneitem_set_visible";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_SET_VISIBLE_SUCCESS = "set_visible_success";
    
    const MESSAGE_called = "拦截到函数调用";
    const MESSAGE_returned = "函数返回";
    const MESSAGE_ON_SUCCESS = "修改源可见性操作完成";
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
    function initHook_set_visible() {
        const funcAddr = getFunctionAddress(FUNCTION_SET_VISIBLE_NAME);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: FUNCTION_SET_VISIBLE_NAME,
                    symbol: FUNCTION_SET_VISIBLE_SYMBOL
                });
                this.visible = args[1];
                const item_pointer = new NativePointer(args[0]);
                console.log(item_pointer);
                this.source_name = item_pointer.add(32).readPointer().readPointer().readCString(-1);
                console.log(this.source_name);
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_SET_VISIBLE_NAME,
                    symbol: FUNCTION_SET_VISIBLE_SYMBOL
                });
                sendEvent(EVENT_SET_VISIBLE_SUCCESS, {
                    message: MESSAGE_ON_SUCCESS,
                    flag: retval == 1 ? "true" : "false",
                    visible: this.visible,
                    source_name: this.source_name,
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
        initHook_set_visible();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})(); 