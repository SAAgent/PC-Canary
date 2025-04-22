(function () {
    // 脚本设置
    const FUNCTION_NAME_SAVE = "OBSBasic::Save";
    const FUNCTION_SYMBOL_SAVE = "_ZN8OBSBasic4SaveEPKc";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";

    const MESSAGE_CALLED = "拦截到函数调用";
    const MESSAGE_RETURNED = "函数返回";
    const MESSAGE_SCRIPT_INITIALIZED = "监控脚本已启动";
    const MESSAGE_HOOK_INSTALLED = "监控钩子安装完成，等待操作...";

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

    // 初始化钩子 - 监听OBSBasic::Save获取场景集合配置文件路径
    function hookSaveSceneCollection() {
        const funcAddr = getFunctionAddress(FUNCTION_SYMBOL_SAVE);
        if (!funcAddr) {
            return;
        }

        // 监听OBSBasic::Save函数
        Interceptor.attach(funcAddr, {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_CALLED,
                    function: FUNCTION_NAME_SAVE,
                    symbol: FUNCTION_SYMBOL_SAVE
                });
                this.path = args[1].readCString();
                console.log("this.path is: ", this.path);
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_RETURNED,
                    function: FUNCTION_NAME_SAVE,
                    symbol: FUNCTION_SYMBOL_SAVE,
                    path: this.path,
                });
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_SCRIPT_INITIALIZED
        });

        // 初始化各个钩子
        hookSaveSceneCollection();
        hookSaveFunction();

        sendEvent("hook_installed", {
            message: MESSAGE_HOOK_INSTALLED
        });
    }

    // 启动脚本
    initHook();
})(); 