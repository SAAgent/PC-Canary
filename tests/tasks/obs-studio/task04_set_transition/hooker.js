// OBS切换场景钩子脚本
// 用于监听OBS的切换场景操作

(function () {
    // 脚本设置
    const FUNCTION_SetTransition = "_ZN8OBSBasic13SetTransitionE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEE";
    const OFFSET_info = 0x150;
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
    function initSetTransitionHook() {

        const SetTransitionFuncAddr = getFunctionAddress(FUNCTION_SetTransition);
        if (!SetTransitionFuncAddr) {
            return;
        }

        Interceptor.attach(SetTransitionFuncAddr, {
            onEnter: function(args) {
                sendEvent("setTransition_called", {
                    message: MESSAGE_called,
                    function: "OBSBasic::SetTransition"
                });
                const transition = new NativePointer(args[1]);
                this.transition = transition;
            },

            onLeave: function(retval) {
                sendEvent("setTransition_returned", {
                    message: MESSAGE_returned,
                    function: "OBSBasic::SetTransition"
                });
                const val_pointer = this.transition.readPointer();
                console.log(val_pointer);
                const info_pointer = val_pointer.add(OFFSET_info);
                console.log(info_pointer);
                const id_pointer = info_pointer.readPointer();
                console.log(id_pointer);
                const id = id_pointer.readCString(-1);
                console.log('transition id: ', id);
                sendEvent("current_transition", {
                    transition: id,
                    message: `当前转场动画名称: ${id}`
                })
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        initSetTransitionHook();
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})(); 