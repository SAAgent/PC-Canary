(function () {
    // 脚本设置
    const FUNCTION_NAME = "OBSBasicSettings::SaveStream1Settings";
    const FUNCTION_SYMBOL = "_ZN16OBSBasicSettings19SaveStream1SettingsEv";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_ON_SUCCESS = "current_stream_service";

    const PAYLOAD_SUCCESS = "stream_service";
    
    const MESSAGE_called = "拦截到函数调用";
    const MESSAGE_returned = "函数返回";
    const MESSAGE_ON_SUCCESS = "设置直播服务操作成功"
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
    function initHook_inner() {
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
                const this_ptr = new NativePointer(args[0]);
                this.this_ptr = this_ptr;
            },
            
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, {
                    message: MESSAGE_returned,
                    function: FUNCTION_NAME,
                    symbol: FUNCTION_SYMBOL
                });
                const main_offset = 40;
                const this_ptr = this.this_ptr;
                // console.log(this_ptr);
                const main_ptr = this_ptr.add(main_offset);
                // console.log(main_ptr);
                const main = main_ptr.readPointer();
                // console.log(main);
                const service_offset = 640;
                const service_pointer = main.add(service_offset);
                // console.log(service_pointer);
                const val = service_pointer.readPointer();
                // console.log(val);
                const settings_offset = 24;
                const settings_pointer = val.add(settings_offset);
                // console.log(settings_pointer);
                const settings = settings_pointer.readPointer();
                // console.log(settings);
                const obs_data_get_string = new NativeFunction(Module.findExportByName(null, "obs_data_get_string"), 'pointer', ['pointer', 'pointer']);
                // console.log(obs_data_get_string);
                const name_ptr = obs_data_get_string(settings, Memory.allocUtf8String('service'));
                const name = name_ptr.readCString(-1);
                // console.log(name);
                sendEvent(EVENT_ON_SUCCESS, {
                    message: MESSAGE_ON_SUCCESS,
                    [PAYLOAD_SUCCESS]: name
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
        initHook_inner();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})(); 