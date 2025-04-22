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
        let function_name = "create_binding";
        let symbol_name = "create_binding";

        Interceptor.attach(getFunctionAddress(function_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
                const name = args[0].add(8).readPointer().readCString(-1);
                this.name = name;
                console.log(name);
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name
                });
                sendEvent("set_hotkey_success", {
                    message: "创建新热键完成",
                    name: this.name
                });
            }
        });
    }

    function hook_obs_save_hotkey() {
        const function_name = "OBSBasicSettings::SaveSettings";
        const symbol_name = "_ZN16OBSBasicSettings12SaveSettingsEv";
        
        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
                const main_offset = 0x28;
                const main = args[0].add(main_offset).readPointer();
                const getConfigAddr = getFunctionAddress("_ZNK8OBSBasic6ConfigEv");
                const getConfig = new NativeFunction(getConfigAddr, 'pointer', ['pointer']);
                const config_ptr = getConfig(main);
                const file_name = config_ptr.readPointer().readCString(-1);
                this.file = file_name;
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name
                });
                sendEvent("save_success", {
                    message: "配置文件保存完毕",
                    file: this.file
                });
            }
        });
    }

    function hook_obs_hotkey_press() {
        const function_name = "obs_hotkey_pair_first_func";
        const symbol_name = "obs_hotkey_pair_first_func";
        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                sendEvent(EVENT_ON_ENTER, {
                    message: MESSAGE_called,
                    function: function_name,
                    symbol: symbol_name
                });
                const name_offset = 0x8;
                const name = args[2].add(name_offset).readPointer().readCString(-1);
                this.name = name;
                this.pressed = args[3];
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: function_name,
                    symbol: symbol_name
                });
                sendEvent("hotkey_press", {
                    message: "热键被触发",
                    name: this.name,
                    pressed: this.pressed == 0x1 ? "true" : "false"
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
        hook_obs_save_hotkey();
        hook_obs_hotkey_press();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})(); 